import express, { response } from "express";
import axios from "axios";
import encode from "nodejs-base64-encode";
const base64url = require("base64url");
const userOps = require("./user");

// Metadata - simplewebauthn
import { MetadataService } from "@simplewebauthn/server";
import { MetadataStatement } from "@simplewebauthn/server/dist/metadata/metadataService";
import verifyAttestationWithMetadata = require("@simplewebauthn/server/dist/metadata/verifyAttestationWithMetadata");
import decodeAttestationObject = require("@simplewebauthn/server/dist/helpers/decodeAttestationObject");
import parseAuthenticatorData = require("@simplewebauthn/server/dist/helpers/parseAuthenticatorData");
import convertX509CertToPEM = require("@simplewebauthn/server/dist/helpers/convertX509CertToPEM");
import verifySignature = require("@simplewebauthn/server/dist/helpers/verifySignature");
import toHash = require("@simplewebauthn/server/dist/helpers/toHash");
import decodeCredentialPublicKey = require("@simplewebauthn/server/dist/helpers/decodeCredentialPublicKey");
import convertCOSEtoPKCS = require("@simplewebauthn/server/dist/helpers/convertCOSEtoPKCS");

const getCertificateInfo = require("@simplewebauthn/server/dist/helpers/getCertificateInfo");

let config = require("./../../config.json");

var challenge: any;
var auth: any;
var authClient: any;
var token: any;

export default ({ app }: { app: express.Application }) => {
  /**
   * Health Check endpoints
   */
  app.get("/status", (req, res) => {
    res.status(200).end("Connection Successful");
  });
  app.head("/status", (req, res) => {
    res.status(200).end();
  });

  /**
   * Credential Creation Options
   */
  const appId = `{'appId':'http://localhost:61904'}`;
  var requestId;

  app.post("/attestation/options", async (req, res) => {
    console.log(`\n\nRequest @ /attestation/options`);
    console.log("user >> ", req.body.username, req.body.displayName);

    var attestation = req.body.attestation;
    var authenticatorSelection = req.body.authenticatorSelection;
    var extensions = { "example.extension": true };
    var attestationLogic = req.body.attestation == "direct" ? "direct" : "none";

    // Set user data required to create a user in wso2is
    var userData = {
      familyName: req.body.displayName.split(" ")[1],
      givenName: req.body.displayName.split(" ")[0],
      userName: req.body.username,
      password: "password",
      homeEmail:
        req.body.displayName.split(" ")[0].toLowerCase() + `_home@gmail.com`,
      workEmail:
        req.body.displayName.split(" ")[0].toLowerCase() + `_work@gmail.com`,
      attestationClaim: req.body.attestation.toUpperCase(),
    };

    // Create user
    const userCreationResponse = await userOps.createUser(userData);
    if (!userCreationResponse) {
      res.send({
        status: "failed",
        errorMessage: "Unable to create a user",
      });
    }

    authClient = encode.encode(`${config.sampleAppId}:${config.clientSecret}`, "base64");

    // password grant call
    await axios({
      method: "post",
      url: `https://${config.host}:9443/oauth2/token?grant_type=password&username=${userData.userName}&password=${userData.password}&scope=internal_login`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${authClient}`,
      }
    }).then((response) => {
      token = response.data["access_token"];
    }).catch((error) => {
      console.log("Error while retrieving access token", error);
    })

    auth = encode.encode(`${userData.userName}:${userData.password}`, "base64");

    if (
      req.body.authenticatorSelection &&
      req.body.authenticatorSelection.requireResidentKey == false
    ) {
      // start-registration
      await axios({
        method: "post",
        url: `https://${config.host}:9443/api/users/v2/me/webauthn/start-registration`,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Bearer ${token}`,
        },
        data: appId,
      })
        .then((usernamelessRegistrationResponse) => {
          requestId = usernamelessRegistrationResponse.data.requestId;

          // Response to the conformance tools
          var returnData = {
            status: "ok",
            errorMessage: "",
            rp:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.rp,
            user:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.user,
            challenge:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.challenge,
            pubKeyCredParams:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.pubKeyCredParams,
            timeout:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.timeout,
            excludeCredentials: [
              {
                type: "public-key",
                id: "rnInB99skrSHLwQJpAio3W2S5RMHGYGudqdobiUImDI",
              },
            ],
            authenticatorSelection: {
              requireResidentKey: usernamelessRegistrationResponse.data.publicKeyCredentialCreationOptions.authenticatorSelection.requireResidentKey,
              userVerification: usernamelessRegistrationResponse.data.publicKeyCredentialCreationOptions.authenticatorSelection.userVerification
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
          // console.log("start registration error", err);
          res.send({
            status: "failed",
            errorMessage: err.message,
          });
        });
    } else {
      // start-usernameless-registration
      await axios({
        method: "post",
        url: `https://${config.host}:9443/api/users/v2/me/webauthn/start-usernameless-registration`,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Bearer ${token}`,
        },
        data: appId,
      })
        .then((usernamelessRegistrationResponse) => {
          requestId = usernamelessRegistrationResponse.data.requestId;

          // Response to the conformance tools
          var returnData = {
            status: "ok",
            errorMessage: "",
            rp:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.rp,
            user:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.user,
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
   * Authenticator Attestation Response
   */
  app.post("/attestation/result", async (req, res) => {
    console.log(`\n\nRequest @ /attestation/results`);

    // Arrange data to be sent to wso2is
    var data = {
      credential: {
        clientExtensionResults: {},
        id: req.body.id,
        response: req.body.response,
        type: req.body.type,
      },
      requestId: requestId,
    };

    // // 1. Read AAGUID from the request
    // try {
    //   const { id, rawId, response, type } = req.body;
    //   const { attestationObject, clientDataJSON } = response;
    //   const { fmt, attStmt, authData } = decodeAttestationObject.default(
    //     attestationObject
    //   );
    //   const { alg, sig, x5c } = attStmt;
    //   const {
    //     rpIdHash,
    //     aaguid,
    //     credentialPublicKey,
    //   } = parseAuthenticatorData.default(authData);

    //   console.log('fmt-------------', fmt);
    //   console.log('aaguid-------------', Number.parseInt(aaguid.toString("hex"), 16));

    //   let verified = false;

      // const clientDataHash = toHash.default(
      //   base64url.default.toBuffer(response.clientDataJSON)
      // );
      // var signatureBase = Buffer.concat([authData, clientDataHash]);

      // if (x5c) {
      //   console.log("------------- x5c --------------");
      //   var leafCert = convertX509CertToPEM.default(x5c[0]);

      //   var {
      //     subject,
      //     basicConstraintsCA,
      //     version,
      //     notBefore,
      //     notAfter,
      //   } = getCertificateInfo.default(leafCert);

      //   var { OU, CN, O, C } = subject;

      //   /**
      //    * For FIDO-U2F Attestation
      //    *
      //    */
      //   if (fmt == "fido-u2f") {
      //     const aaguidToHex = Number.parseInt(aaguid.toString("hex"), 16);
      //     if (aaguidToHex !== 0x00) {
      //       throw new Error(`AAGUID '${aaguidToHex}' was not expected value`);
      //     }
      //   }

    //     /**
    //      * For PACKED Attestation
    //      * METADATA validation
    //      */
    //     if (fmt == "packed") {
    //       if (OU !== "Authenticator Attestation") {
    //         throw new Error(`Certificate not good before 1 (Packed|Full)`);
    //       }
    //       if (!CN) {
    //         throw new Error(`Certificate not good before 2 (Packed|Full)`);
    //       }
    //       if (!O) {
    //         throw new Error(`Certificate not good before 3 (Packed|Full)`);
    //       }
    //       if (!C || C.length !== 2) {
    //         throw new Error(`Certificate not good before 4 (Packed|Full)`);
    //       }
    //       if (basicConstraintsCA) {
    //         throw new Error(`Certificate not good before 5 (Packed|Full)`);
    //       }
    //       if (version !== 3) {
    //         throw new Error(`Certificate not good before 6 (Packed|Full)`);
    //       }
    //       let now = new Date();
    //       if (notBefore > now) {
    //         throw new Error(`Certificate not good before 7 (Packed|Full)`);
    //       }
    //       now = new Date();
    //       if (notAfter < now) {
    //         throw new Error(`Certificate not good before 8 (Packed|Full)`);
    //       }

    //       var metadataStatement: MetadataStatement = await MetadataService.getStatement(
    //         aaguid
    //       );

    //       if (metadataStatement) {
    //         var verification: any = verifyAttestationWithMetadata.default(
    //           metadataStatement,
    //           alg,
    //           x5c
    //         );
    //       }
    //     }
    //     verifySignature.default(sig, signatureBase, leafCert);
    //   } else {
    //     const cosePublicKey = decodeCredentialPublicKey.default(
    //       credentialPublicKey
    //     );
    //     const kty = cosePublicKey.get(convertCOSEtoPKCS.COSEKEYS.kty);
    //     if (!kty) {
    //       throw new Error("COSE public key was missing kty (Packed|Self)");
    //     }
    //   }
    // } catch (error) {
    //   res.send({
    //     status: "failed",
    //     errorMessage: error.message,
    //   });
    // }

    // // For metadata verification
    // // Used Simplewebauthn
    // var dataToVerification = {
    //   credential: {
    //     rawId: req.body.rawId,
    //     clientExtensionResults: {},
    //     id: req.body.id,
    //     response: req.body.response,
    //     type: req.body.type,
    //   },
    //   requestId: requestId,
    // };

    // Finish registration request
    var x = await axios({
      method: "post",
      url: `https://${config.host}:9443/api/users/v2/me/webauthn/finish-registration`,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      data: data,
    })
      .then((response) => {
        console.log("\n\nfinish-registration response --------------------->", response, "\n\n");
        res.send({
          status: "ok",
          errorMessage: "",
        });
      })
      .catch((error) => {
        // console.log("finish-registration error >> ", error);
        res.send({
          status: "failed",
          errorMessage: error.message,
        });
      });
  });

  /**
   * Delete users.
   */
  app.get("/adapter/users/delete", async (req, res) => {
    console.log(`\n\nRequest @ /adapter/users/delete`);

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
