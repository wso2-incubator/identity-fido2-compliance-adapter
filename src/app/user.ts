import axios from "axios";

const fs = require("fs");
const readline = require("readline");
const qs = require("qs");

const config = require("./../../config.json");

/**
 * Find availability of a user with SCIM2 API.
 */
const searchUser = async (req) => {
    // Set filter for user search.
    const filter = `userName sw ${req.body.username}`;
    const url = "https://" + config.host + (config.tenantName && config.tenantName !== ""
        ? "/t/" + config.tenantName + "/" : "/") + "scim2/Users/.search";
    let authToken = "";

    if (config.isCloudSetup) {
        authToken = await obtainBearerToken();

        if (authToken === "") {
            console.log("Error retrieving bearer token!");
        } else {
            authToken = "Bearer " + authToken;
        }
    } else {
        authToken = `Basic ${config.basicAuthCredentials}`;
    }

    const searchUserdata = {
        attributes: [ "name.familyName", "userName" ],
        count: 100,
        domain: "PRIMARY",
        filter: filter,
        schemas: [ "urn:ietf:params:scim:api:messages:2.0:SearchRequest" ],
        startIndex: 1
    };
    const headers = {
        Authorization: authToken,
        "Content-Type": "application/scim+json"
    };

    return await axios({
        data: searchUserdata,
        headers: headers,
        method: "post",
        url: url
    });
};

/**
 * Create user with SCIM2 API.
 */
const createUser = async (userData) => {
    const data = JSON.stringify({
        displayName: userData.givenName + " " + userData.familyName,
        emails: [
            {
                primary: true,
                type: "home",
                value: config.isCloudSetup ? `${config.userStoreDomain}/${userData.homeEmail}` : userData.homeEmail
            },
            {
                type: "work",
                value: userData.workEmail
            }
        ],
        name: {
            familyName: userData.familyName,
            givenName: userData.givenName
        },
        password: userData.password,
        schemas: [],
        userName: userData.userName
    });

    let userCreated = false;

    try {
        const url = "https://" + config.host + (config.tenantName && config.tenantName !== ""
            ? "/t/" + config.tenantName + "/" : "/") + "scim2/Users";
        let authToken = "";

        if (config.isCloudSetup) {
            authToken = await obtainBearerToken();

            if (authToken === "") {
                console.log("Error retrieving bearer token!");
            } else {
                authToken = "Bearer " + authToken;
            }
        } else {
            authToken = `Basic ${config.basicAuthCredentials}`;
        }

        const headers = {
            Authorization: authToken,
            "Content-Type": "application/json"
        };

        await axios({
            data: data,
            headers: headers,
            method: "post",
            url: url
        }).then(response => {
            // Append succesfully created users to a file.
            if (response.status == 201) {
                // eslint-disable-next-line @typescript-eslint/no-empty-function
                fs.appendFile("data/user_list.txt", response?.data?.id + "\n", function () {});
                userCreated = true;
            }
        }).catch((error) => {
            if (error.response.status == 409) {
                console.log("User already exists in the server!");
                userCreated = true;
            } else {
                console.error(error);
                userCreated = false;
            }
        });
    } catch (error) {
        console.error(error);
        userCreated = false;
    }

    return userCreated;
};

/**
 * Delete stored set of users with SCIM2 API.
 */
const deleteUsers = async () => {
    const fileStream = fs.createReadStream("data/user_list.txt");
    const readLine= readline.createInterface({
        crlfDelay: Infinity,
        input: fileStream
    });

    let userCount = 0;
    let deletedCount = 0;

    const url = "https://" + config.host + (config.tenantName && config.tenantName !== ""
        ? "/t/" + config.tenantName + "/" : "/") + "scim2/Users";
    let authToken = "";

    if (config.isCloudSetup) {
        authToken = await obtainBearerToken();

        if (authToken === "") {
            console.log("Error retrieving bearer token!");
        } else {
            authToken = "Bearer " + authToken;
        }
    } else {
        authToken = `Basic ${config.basicAuthCredentials}`;
    }

    const headers = {
        Authorization: authToken,
        "Content-Type": "application/json"
    };

    for await (const userId of readLine) {
        userCount += 1;

        try {
            await axios({
                headers: headers,
                method: "delete",
                url: url + `/${userId}`
            }).then(response => {
                if (response.status == 204) {
                    deletedCount += 1;
                    console.log(`User deleted with the id ${userId}`);
                } else {
                    console.log(`Error deleting the user with id ${userId}`);
                }
            });
        } catch (error) {
            console.log(`Error deleting the user with id ${userId}`);
        }
    }

    // eslint-disable-next-line @typescript-eslint/no-empty-function
    fs.writeFile("data/user_list.txt", "", function () {});
    console.log(`${deletedCount} users deleted from ${userCount} user records.`);

    return `${deletedCount} users deleted from ${userCount} user records.`;
};

const obtainBearerToken = async () => {
    let token = "";
    const headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    };
    const data = qs.stringify({
        client_id: config.bearerTokenClientId,
        grant_type: config.bearerTokenGrantType,
        password: config.bearerTokenPassword,
        scope: config.bearerTokenScope,
        username: config.bearerTokenUsername
    });

    await axios({
        data: data,
        headers: headers,
        method: "post",
        url: `https://${config.host}/oauth2/token`
    }).then((response) => {
        token = response.data["access_token"];
    }).catch((error) => {
        console.log("Error while retrieving bearer token", error);
    });

    return token;
};

const formatUsername = (providedName) => {
    // eslint-disable-next-line no-useless-escape, max-len
    const validRegex = /^[^!@#$%\^&\*\(\)_\+\-=\[\]{};':"\\|,.<>\/?]+(.)*[^!@#$%\^&\*\(\)_\+\-=\[\]{};':"\\|,.<>\/?]+@(.)+\.(.)+$/;
    // eslint-disable-next-line no-useless-escape
    const invalidRegex1 = /[!@#$%\^&\*\(\)_\+\-=\[\]{};':"\\|,.<>\/?]{2,}/;

    if (config.isCloudSetup) {
        if (providedName.includes("@")) {
            providedName = `${config.userStoreDomain}/fido${providedName}`;
        } else {
            providedName = `${config.userStoreDomain}/fido${providedName}@fidotest.com`;
        }
    }

    if (!validRegex.test(providedName)) {
        providedName = providedName.split("@")[0] + "post@fidotest.com";

        if (invalidRegex1.test(providedName)) {
            return [ true, providedName.replace(invalidRegex1, "") ];
        }

        return [ true, providedName ];
    } else if (invalidRegex1.test(providedName)) {
        return [ true, providedName.replace(invalidRegex1, "") ];
    }

    return [ false, providedName ];
};

module.exports = {
    createUser, deleteUsers, formatUsername, searchUser
};
