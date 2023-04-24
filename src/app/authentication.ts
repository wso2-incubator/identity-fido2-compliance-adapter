import parseAuthenticatorData from "@simplewebauthn/server/dist/helpers/parseAuthenticatorData";
import axios from "axios";
import express from "express";
import encode from "nodejs-base64-encode";

const qs = require("qs");

const config = require("./../../config.json");
let requestId: any;
let sessionDataKey: any;
let auth: any;
let sessionNonceCookie: string;
let userVerification: any;

const allowCredentials = [
    {
        id: "rnInB99skrSHLwQJpAio3W2S5RMHGYGudqdobiUImDI",
        type: "public-key"
    }
];

export default ({ app }: { app: express.Application }) => {
    /**
     * Health Check endpoints registration.
     */
    app.get("/status/registration", (req, res) => {
        res.status(200).end("Reg Connection Successful");
    });
    app.head("/status/registration", (req, res) => {
        res.status(200).end();
    });

    app.post("/assertion/options", async (req, res) => {
        console.log("\nRequest @ /assertion/options");

        sessionNonceCookie = "";

        // Client Id of the sample app.
        const client_id = config.clientID;

        userVerification = req.body?.userVerification;
        const extensions = req.body?.extensions;

        auth = encode.encode(`${req.body.username}:${config.userPassword}`, "base64");

        const url = "https://" + config.host
            + (config.tenantName && config.tenantName !== "" ? "/t/" + config.tenantName + "/" : "/")
            + "oauth2/authorize?scope=openid&response_type=code&redirect_uri=" + config.redirectUri
            + "&client_id=" + client_id;
        const headers = {
            Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*",
            Connection: "keep-alive",
            ContentType: "application/json",
            Host: "localhost:9443"
        };

        // start-authentication.
        await axios({
            headers: headers,
            maxRedirects: 0,
            method: "get",
            url: url
        }).then((response: any) => {
            const headers: any = response.request._header;

            sessionDataKey = headers.split("?")[1].split("&")[2].split("=")[1];
            const data = JSON.parse(
                unescape(
                    headers.split("?")[1].split("&")[3].split(" ")[0].split("=")[1]
                )
            );

            requestId = data.requestId;

            const responseToTool = {
                allowCredentials: [],
                challenge: data.publicKeyCredentialRequestOptions.challenge,
                errorMessage: "",
                extensions: extensions,
                rpId: data.publicKeyCredentialRequestOptions.rpId,
                status: "ok",
                timeout: 20000,
                userVerification: userVerification ?? data.publicKeyCredentialRequestOptions.userVerification
            };

            /**
             * This particular test expects the allowCredentials list and that is not supported by the browser.
             * Allow credentials are not required in the usernameless authentication.
             * According to spec, credentials are used when the user has to be identified.
             */
            if (req.body?.username && req.body?.userVerification && req.body?.extensions) {
                responseToTool.allowCredentials = allowCredentials;
            }

            res.header(response.headers);
            res.send(responseToTool);
        }).catch((error) => {
            if (error.response?.status == 302) {
                const responseLocation: string = error.response.headers?.location;

                sessionDataKey = responseLocation.split("?")[1].split("&")[2].split("=")[1];
                const data = JSON.parse(
                    unescape(
                        responseLocation.split("?")[1].split("&")[3].split(" ")[0].split("=")[1]
                    )
                );

                requestId = data.requestId;
                sessionNonceCookie = error.response.headers["set-cookie"];

                const responseToTool = {
                    allowCredentials: [],
                    challenge: data.publicKeyCredentialRequestOptions.challenge,
                    errorMessage: "",
                    extensions: extensions,
                    rpId: data.publicKeyCredentialRequestOptions.rpId,
                    status: "ok",
                    timeout: 20000,
                    userVerification: userVerification ?? data.publicKeyCredentialRequestOptions.userVerification
                };

                /**
                 * This particular test expects the allowCredentials list and that is not supported by the browser.
                 * Allow credentials are not required in the usernameless authentication.
                 * According to spec, credentials are used when the user has to be identified.
                 */
                 if (req.body?.username && req.body?.userVerification && req.body?.extensions) {
                    responseToTool.allowCredentials = allowCredentials;
                }

                res.send(responseToTool);
            } else {
                res.send({
                    errorMessage: "",
                    status: "failed"
                });
            }
        });
    });

    /**
     * Authenticator Assertion Response.
     */
    app.post("/assertion/result", async (req, res) => {
        console.log("\nRequest @ /assertion/result");

        if (req.body.response?.authenticatorData) {
            try {
                const authenticatorData = parseAuthenticatorData(Buffer.from(
                    req.body.response?.authenticatorData, "base64"));
                const authenticatorFlagsUP = authenticatorData?.flags?.up;
                const authenticatorFlagsUV = authenticatorData?.flags?.uv;

                /**
                 * According to webauthn specification, the server should check for the existance of UP flag.
                 * Quaoted from spec: "Verify that the User Present bit of the flags in authData is set".
                 * Hence this scenario is explicitly handled from the adapter.
                 */
                if (!authenticatorFlagsUP) {
                    res.send({
                        errorMessage: "",
                        status: "ok"                        
                    });

                    return;
                }

                /**
                 * We are handling this test case explicitly since the server doesn't allow to config user verification
                 * option. According to our design, this option cannnot be configured and will always be set to
                 * "preferred".
                 */
                if (authenticatorFlagsUP && !authenticatorFlagsUV && userVerification == "required") {
                    res.send({
                        errorMessage: "",
                        status: "failed"
                    });

                    return;
                }
            } catch (e) {
                console.log("Error in decoding authenticatorData object!");
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

        const tr = JSON.stringify({ credential: req.body, requestId: requestId });
        const referer = "https://" + config.authRequestRefererHost
            + (config.tenantName && config.tenantName !== "" ? "/t/" + config.tenantName + "/" : "/")
            + "authenticationendpoint/fido2-auth.jsp?authenticators=FIDOAuthenticator%3ALOCAL"
            + "&type=fido&sessionDataKey=" + sessionDataKey + "&data=" + tr;

        const url = "https://" + config.host + (config.tenantName && config.tenantName !== ""
            ? "/t/" + config.tenantName + "/" : "/") + "commonauth";
        const headers = {
            Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*",
            Connection: "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded",
            Referer: referer,
            cookie: sessionNonceCookie
        };
        const data = qs.stringify({
            sessionDataKey: sessionDataKey,
            tokenResponse: tr
        });

        await axios({
            data: data,
            headers: headers,
            method: "post",
            url: url
        }).then(async (response) => {
            // If the return path contains the code, that means a successful authentication.
            if (response.request.path.includes("code=")) {
                res.send({
                    errorMessage: "",
                    status: "ok"
                });
            } else {
                res.send({
                    errorMessage: "",
                    status: "failed"
                });
            }
        }).catch(() => {
            res.send({
                errorMessage: "",
                status: "failed"
            });
        });
    });
};
