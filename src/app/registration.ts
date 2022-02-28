import express, { response } from "express";
import axios from "axios";
import encode from "nodejs-base64-encode";

const base64url = require("base64url");
const userOps = require("./user");
const getCertificateInfo = require("@simplewebauthn/server/dist/helpers/getCertificateInfo");

let config = require("./../../config.json");

var challenge: any;
var authClient: any;
var token: any;
var invalidUsername: any = false;
var providedUsername = "";

export default ({ app }: { app: express.Application }) => {
  /**
   * Health Check endpoints.
   */
  app.get("/status", (req, res) => {
    res.status(200).end("Connection Successful");
  });
  app.head("/status", (req, res) => {
    res.status(200).end();
  });

  /**
   * Credential Creation Options.
   */
  const appId = `{'appId':'http://localhost:61904'}`;
  var requestId;

  app.post("/attestation/options", async (req, res) => {
    console.log(`\nRequest @ /attestation/options`);
    console.log("user >> ", req.body.username, req.body.displayName);

    var extensions = { "example.extension": true };
    var attestationLogic = req.body.attestation == "direct" ? "direct" : "none";
    var username = userOps.formatUsername(req.body.username);
    invalidUsername = username[0];
    username = username[1];
    providedUsername = req.body.username;

    // Set user data required to create a user in wso2is.
    var userData = {
      familyName: req.body.displayName.split(" ")[1],
      givenName: req.body.displayName.split(" ")[0],
      userName: username,
      password: config.userPassword,
      homeEmail:
        req.body.displayName.split(" ")[0].toLowerCase() + `_home@gmail.com`,
      workEmail:
        req.body.displayName.split(" ")[0].toLowerCase() + `_work@gmail.com`
    };

    // Create user.
    const userCreationResponse = await userOps.createUser(userData);
    if (!userCreationResponse) {
      res.send({
        status: "failed",
        errorMessage: "Unable to create a user",
      });
    }

    authClient = encode.encode(`${config.clientID}:${config.clientSecret}`, "base64");
    var url = `https://${config.host}` + (config.tenantName && config.tenantName !== "" ? `/t/${config.tenantName}/` : "/") + `oauth2/token?grant_type=password&username=${userData.userName}&password=${userData.password}&scope=internal_login`;

    // Obtain an access token using the password grant call and 'internal_login' scope.
    await axios({
      method: "post",
      url: url,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${authClient}`,
      }
    }).then((response) => {
      token = response.data["access_token"];
    }).catch((error) => {
      console.log("Error while retrieving access token", error);
    })

    if (
      req.body.authenticatorSelection &&
      req.body.authenticatorSelection.requireResidentKey == false
    ) {
      // start-registration
      await axios({
        method: "post",
        url: `https://${config.host}` + (config.tenantName && config.tenantName !== "" ? `/t/${config.tenantName}/` : "/") + `api/users/v2/me/webauthn/start-registration`,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Bearer ${token}`,
        },
        data: appId,
      })
        .then((usernamelessRegistrationResponse) => {
          requestId = usernamelessRegistrationResponse.data.requestId;

          var user = usernamelessRegistrationResponse.data.publicKeyCredentialCreationOptions.user;
          if (config.isCloudSetup) {
            if (invalidUsername) {
              user.name = providedUsername;
            } else {
              user.name = user.name.split("@")[0].substring(4);
            }
          }

          // Construct response to the conformance tools.
          var returnData = {
            status: "ok",
            errorMessage: "",
            rp:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.rp,
            user: user,
            challenge:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.challenge,
            pubKeyCredParams:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.pubKeyCredParams,
            timeout:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.timeout,
            excludeCredentials: 
              usernamelessRegistrationResponse.data.publicKeyCredentialCreationOptions.excludeCredentials,
            authenticatorSelection: {
              requireResidentKey: usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.authenticatorSelection.requireResidentKey,
              userVerification: usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.authenticatorSelection.userVerification
            },
            attestation: attestationLogic,
            extensions: extensions,
          };

          challenge =
            usernamelessRegistrationResponse.data
              .publicKeyCredentialCreationOptions.challenge;

          res.send(returnData);
        })
        .catch((err) => {
          res.send({
            status: "failed",
            errorMessage: err.message,
          });
        });
    } else {
      // start-usernameless-registration
      await axios({
        method: "post",
        url: `https://${config.host}` + (config.tenantName && config.tenantName !== "" ? `/t/${config.tenantName}/` : "/") + `api/users/v2/me/webauthn/start-usernameless-registration`,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Bearer ${token}`,
        },
        data: appId,
      })
        .then((usernamelessRegistrationResponse) => {
          requestId = usernamelessRegistrationResponse.data.requestId;

          var user = usernamelessRegistrationResponse.data.publicKeyCredentialCreationOptions.user;
          if (config.isCloudSetup) {
            if (invalidUsername) {
              user.name = providedUsername;
            } else {
              user.name = user.name.split("@")[0].substring(4);
            }
          }

          // Response to the conformance tools
          var returnData = {
            status: "ok",
            errorMessage: "",
            rp:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.rp,
            user: user,
            challenge:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.challenge,
            pubKeyCredParams:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.pubKeyCredParams,
            timeout:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.timeout,
            excludeCredentials:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.excludeCredentials,
            authenticatorSelection:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.authenticatorSelection,
            attestation:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.attestation,
            extensions:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.extensions,
          };

          challenge =
            usernamelessRegistrationResponse.data
              .publicKeyCredentialCreationOptions.challenge;

          res.send(returnData);
        })
        .catch((err) => {
          console.log(">>> err >>> ", err);

          res.send({
            status: "failed",
            errorMessage: err.message,
          });
        });
    }
  });

  /**
   * Authenticator Attestation Response.
   */
  app.post("/attestation/result", async (req, res) => {
    console.log(`\nRequest @ /attestation/results`);

    // Arrange data to be sent to the server.
    var data = {
      credential: {
        clientExtensionResults: req.body.getClientExtensionResults ?? {},
        id: req.body.id,
        response: req.body.response,
        type: req.body.type,
      },
      requestId: requestId,
    };

    // Finish registration request.
    var x = await axios({
      method: "post",
      url: `https://${config.host}` + (config.tenantName && config.tenantName !== "" ? `/t/${config.tenantName}/` : "/") + `api/users/v2/me/webauthn/finish-registration`,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      data: data,
    })
      .then((response) => {
        res.send({
          status: "ok",
          errorMessage: "",
        });
      })
      .catch((error) => {
        res.send({
          status: "failed",
          errorMessage: error.message,
        });
      });
  });

  /**
   * Delete users.
   */
  app.delete("/adapter/users/delete", async (req, res) => {
    console.log(`\nRequest @ /adapter/users/delete`);

    userOps.deleteUsers().then((response) => {
      res.send({
        status: "success",
        message: response,
      });
    }).catch((error) => {
      res.send({
        status: "failed",
        errorMessage: error,
      });
    })
  });
};
