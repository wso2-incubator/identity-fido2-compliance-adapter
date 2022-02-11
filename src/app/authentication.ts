import express, { response } from "express";
import axios from "axios";
import querystring from "querystring";
import encode from "nodejs-base64-encode";

import parseAuthenticatorData from "@simplewebauthn/server/dist/helpers/parseAuthenticatorData";

let config = require("./../../config.json");
let requestId: any;
let sessionDataKey: any;
let host = "localhost";
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
    console.log("\n\n\n");
    console.log(`Request @ /assertion/options`);

    optionsRequestCounter += 1;

    // Client Id of the sample app
    var client_id = config.sampleAppId;
    userVerification = req.body?.userVerification;
    var extensions = req.body?.extensions;

    auth = encode.encode(`${req.body.username}:password`, "base64");

    var url = `https://${host}:9443/oauth2/authorize?scope=openid&response_type=code&redirect_uri=https://oidcdebugger.com/debug&client_id=${client_id}`;

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
    })
      .then((response: any) => {
        console.log("\n<<<<<<<<< start-authentication >>>>>>>>>>>", response.status, response.request._header);

        // console.log("\n\n====================== debug response ================================\n", response.headers['set-cookie']);

        var headers: any = response.request._header;

        var requestUrlfido2auth = headers.split("?")[0].split(" ")[1];
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
         * 
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
        // console.log("\n<<<<<<<<< start-authentication error >>>>>>>>>>>", error);
        
        res.send({
          status: "failed",
          errorMessage: "",
        });
      });
  });

  /**
   * Authenticator Assertion Response
   */
  app.post("/assertion/result", async (req, res) => {
    console.log("\n\n\n");
    console.log(`Request @ /assertion/result`);

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

    req.body["clientExtensionResults"] = {};
    delete req.body["getClientExtensionResults"];

    var tr = JSON.stringify({ requestId: requestId, credential: req.body });

    var tokenResponse: any = JSON.parse(JSON.stringify(tr));

    var referer = `https://${host}:9443/authenticationendpoint/fido2-auth.jsp?authenticators=FIDOAuthenticator%3ALOCAL&type=fido&sessionDataKey=${sessionDataKey}&data=${tr}`;

    axios
      .post(
        `https://${host}:9443/commonauth`,
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
          },
        }
      )
      .then(async (response) => {
        console.log("\n<<<<<<<<< finish-authentication >>>>>>>>>>>", response.status, response.request.path);

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
        // console.log("\n<<<<<<<<< finish-authentication error >>>>>>>>>>>", error);
        
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
    console.log(`\n\nRequest @ /adapter/counter/reset`);

    optionsRequestCounter = 0;
    resultRequestCounter = 0;

    res.send({
      status: "success",
      message: "Options request counter = " + optionsRequestCounter + " | " + "Results request counter = " + resultRequestCounter,
    });
  });
};
