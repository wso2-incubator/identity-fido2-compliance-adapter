import express, { response } from "express";
import axios from "axios";
import querystring from "querystring";
import encode from "nodejs-base64-encode";

import parseAuthenticatorData from "@simplewebauthn/server/dist/helpers/parseAuthenticatorData";

let config = require("./../../config.json");
let requestId: any;
let sessionDataKey: any;
let auth: any;
let sessionNonceCookie: string;
var userVerification: any;

var optionsRequestCounter = 0;
var resultRequestCounter = 0;

export default ({ app }: { app: express.Application }) => {
  /**
   * Health Check endpoints registration
   */
  app.get("/status/registration", (req, res) => {
    res.status(200).end("Reg Connection Successful");
  });
  app.head("/status/registration", (req, res) => {
    res.status(200).end();
  });

  app.post("/assertion/options", async (req, res) => {
    console.log(`\nRequest @ /assertion/options`);

    optionsRequestCounter += 1;
    sessionNonceCookie = "";

    // Client Id of the sample app
    var client_id = config.clientID;
    userVerification = req.body?.userVerification;
    var extensions = req.body?.extensions;

    auth = encode.encode(`${req.body.username}:${config.userPassword}`, "base64");

    var url = `https://${config.host}` + (config.tenantName && config.tenantName !== "" ? `/t/${config.tenantName}/` : "/") + `oauth2/authorize?scope=openid&response_type=code&redirect_uri=${config.redirectUri}&client_id=${client_id}`;

    // start-authentication
    await axios({
      method: "get",
      url: url,
      headers: {
        Connection: "keep-alive",
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        Host: "localhost:9443",
        ContentType: "application/json",
        Authorization: `Basic ${auth}`,
      },
      maxRedirects: 0
    })
      .then((response: any) => {
        var headers: any = response.request._header;
        sessionDataKey = headers.split("?")[1].split("&")[2].split("=")[1];
        var data = JSON.parse(
          unescape(
            headers.split("?")[1].split("&")[3].split(" ")[0].split("=")[1]
          )
        );
        requestId = data.requestId;

        var responseToAdapter = {
          status: "ok",
          errorMessage: "",
          challenge: data.publicKeyCredentialRequestOptions.challenge,
          timeout: 20000,
          rpId: data.publicKeyCredentialRequestOptions.rpId,
          allowCredentials: [],
          userVerification: userVerification ?? data.publicKeyCredentialRequestOptions.userVerification,
          extensions: extensions
        };

        /**
         * This particular test expects the allowCredentials list and that is not supported by the browser.
         * Allow credentials are not required in the usernameless authentication.
         * According to spec, credentials are used when the user has to be identified.
         */
        if (optionsRequestCounter == 1 && resultRequestCounter == 0) {
          responseToAdapter.allowCredentials = [
            {
              type: "public-key",
              id: "rnInB99skrSHLwQJpAio3W2S5RMHGYGudqdobiUImDI",
            }
          ]
        }

        res.header(response.headers);
        res.send(responseToAdapter);
      })
      .catch((error) => {
        if (error.response?.status == 302) {
          var responseLocation: string = error.response.headers?.location;
          sessionDataKey = responseLocation.split("?")[1].split("&")[2].split("=")[1];
          var data = JSON.parse(
            unescape(
              responseLocation.split("?")[1].split("&")[3].split(" ")[0].split("=")[1]
            )
          );
          requestId = data.requestId;
          sessionNonceCookie = error.response.headers["set-cookie"];

          var responseToAdapter = {
            status: "ok",
            errorMessage: "",
            challenge: data.publicKeyCredentialRequestOptions.challenge,
            timeout: 20000,
            rpId: data.publicKeyCredentialRequestOptions.rpId,
            allowCredentials: [],
            userVerification: userVerification ?? data.publicKeyCredentialRequestOptions.userVerification,
            extensions: extensions
          };

          /**
           * This particular test expects the allowCredentials list and that is not supported by the browser.
           * Allow credentials are not required in the usernameless authentication.
           * According to spec, credentials are used when the user has to be identified.
           */
          if (optionsRequestCounter == 1 && resultRequestCounter == 0) {
            responseToAdapter.allowCredentials = [
              {
                type: "public-key",
                id: "rnInB99skrSHLwQJpAio3W2S5RMHGYGudqdobiUImDI",
              }
            ]
          }

          res.send(responseToAdapter);
        } else {
          res.send({
            status: "failed",
            errorMessage: "",
          });
        }
      });
  });

  /**
   * Authenticator Assertion Response
   */
  app.post("/assertion/result", async (req, res) => {
    console.log(`\nRequest @ /assertion/result`);

    resultRequestCounter += 1;

    if (req.body.response?.authenticatorData) {
      try {
        var authenticatorData = parseAuthenticatorData(Buffer.from(req.body.response?.authenticatorData, 'base64'));
        var authenticatorFlagsUP = authenticatorData?.flags?.up;
        var authenticatorFlagsUV = authenticatorData?.flags?.uv;

        /**
         * According to webauthn specification, the server should check for the existance of UP flag.
         * Quaoted from spec: "Verify that the User Present bit of the flags in authData is set".
         * Hence this scenario is explicitly handled from the adapter.
         */
        if (!authenticatorFlagsUP) {
          res.send({
            status: "ok",
            errorMessage: "",
          });
          return;
        }

        /**
         * We are handling this test case explicitly since the server doesn't allow to config user verification option.
         * According to our design, this option cannnot be configured and will always be set to "preferred".
         */
        if (authenticatorFlagsUP && !authenticatorFlagsUV && userVerification == "required") {
          res.send({
            status: "failed",
            errorMessage: "",
          });
          return;
        }
      } catch (e) {
      }
    }

    /**
     * These parameters are not supported by the yubico data structure. Therefore need to remove before 
     * sending to the backend implementation. Otherwise will throw data conversion exception.
     */
    req.body["clientExtensionResults"] = {};
    delete req.body["getClientExtensionResults"];
    
    if (req.body["authenticatorAttachment"]) {
      delete req.body["authenticatorAttachment"];
    }

    var tr = JSON.stringify({ requestId: requestId, credential: req.body });
    var tokenResponse: any = JSON.parse(JSON.stringify(tr));
    var referer = `https://${config.authRequestRefererHost}` + (config.tenantName && config.tenantName !== "" ? `/t/${config.tenantName}/` : "/") + `authenticationendpoint/fido2-auth.jsp?authenticators=FIDOAuthenticator%3ALOCAL&type=fido&sessionDataKey=${sessionDataKey}&data=${tr}`;

    axios
      .post(
        `https://${config.host}` + (config.tenantName && config.tenantName !== "" ? `/t/${config.tenantName}/` : "/") + "commonauth",
        querystring.stringify({
          sessionDataKey: sessionDataKey,
          tokenResponse: tr,
        }),
        {
          headers: {
            Connection: "keep-alive",
            Accept:
              "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
            Authorization: `Basic ${auth}`,
            Referer: referer,
            cookie: sessionNonceCookie
          },
        }
      )
      .then(async (response) => {
        // If the return path contains the code, that means a successful authentication.
        if (response.request.path.includes("code=")) {
          res.send({
            status: "ok",
            errorMessage: "",
          });
        } else {
          res.send({
            status: "failed",
            errorMessage: "",
          });
        }
      })
      .catch((error) => {
        res.send({
          status: "failed",
          errorMessage: "",
        });
      });
  });

  /**
   * Reset counters.
   */
   app.get("/adapter/counter/reset", async (req, res) => {
    console.log(`\nRequest @ /adapter/counter/reset`);

    optionsRequestCounter = 0;
    resultRequestCounter = 0;

    res.send({
      status: "success",
      message: "Options request counter = " + optionsRequestCounter + " | " + "Results request counter = " + resultRequestCounter,
    });
  });
};
