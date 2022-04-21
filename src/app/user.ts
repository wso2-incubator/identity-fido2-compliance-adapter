import axios from "axios";

const fs = require("fs");
const readline = require("readline");
const qs = require('qs');

const config = require("./../../config.json");

/**
 * Find availability of a user with SCIM2 API
 */
const searchUser = async (req) => {
    // Set filter for user search
    let filter = `userName sw ${req.body.username}`;

    let url = `https://${config.host}` + (config.tenantName && config.tenantName !== "" ? `/t/${config.tenantName}/` : "/") + `scim2/Users/.search`;
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

    let searchUserdata = {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
        attributes: ["name.familyName", "userName"],
        filter: filter,
        domain: "PRIMARY",
        startIndex: 1,
        count: 100,
    };

    return await axios({
        method: "post",
        url: url,
        headers: {
            "Content-Type": "application/scim+json",
            Authorization: authToken,
        },
        data: searchUserdata,
    });
};

/**
 * Create user with SCIM2 API
 */
const createUser = async (userData) => {
    let data = JSON.stringify({
        schemas: [],
        name: {
            familyName: userData.familyName,
            givenName: userData.givenName,
        },
        displayName: userData.givenName + " " + userData.familyName,
        userName: userData.userName,
        password: userData.password,
        emails: [{
                primary: true,
                value: config.isCloudSetup ? `${config.userStoreDomain}/${userData.homeEmail}` : userData.homeEmail,
                type: "home"
            },
            {
                value: userData.workEmail,
                type: "work"
            },
        ]
    });

    let userCreated = false;

    try {
        let url = `https://${config.host}` + (config.tenantName && config.tenantName !== "" ? `/t/${config.tenantName}/` : "/") + `scim2/Users`;
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

        await axios({
            method: "post",
            url: url,
            headers: {
                "Content-Type": "application/json",
                Authorization: authToken,
            },
            data: data,
        }).then(response => {
            // Append succesfully created users to a file.
            if (response.status == 201) {
                fs.appendFile("data/user_list.txt", response?.data?.id + "\n", function (err) {});
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
 * Delete stored set of users with SCIM2 API
 */
 const deleteUsers = async (res) => {
    const fileStream = fs.createReadStream("data/user_list.txt");
    const readLine= readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity
    });

    let userCount = 0;
    let deletedCount = 0;

    let url = `https://${config.host}` + (config.tenantName && config.tenantName !== "" ? `/t/${config.tenantName}/` : "/") + `scim2/Users`;
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

    for await (const userId of readLine) {
        userCount += 1;
        try {
            await axios({
                method: "delete",
                url: url + `/${userId}`,
                headers: {
                    "Content-Type": "application/json",
                    Authorization: authToken,
                }
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
    };

    fs.writeFile("data/user_list.txt", "", function (err) {});
    console.log(`${deletedCount} users deleted from ${userCount} user records.`);
    return `${deletedCount} users deleted from ${userCount} user records.`;
};

const obtainBearerToken = async () => {
    let token = "";
    await axios({
        method: "post",
        url: `https://${config.host}/oauth2/token`,
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        data: qs.stringify({
            grant_type: config.bearerTokenGrantType,
            client_id: config.bearerTokenClientId,
            username: config.bearerTokenUsername,
            password: config.bearerTokenPassword,
            scope: config.bearerTokenScope
        })
    }).then((response) => {
        token = response.data["access_token"];
    }).catch((error) => {
        console.log("Error while retrieving bearer token", error);
    });

    return token;
}

const formatUsername = (providedName) => {
    const validRegex = /^[^!@#$%\^&\*\(\)_\+\-=\[\]{};':"\\|,.<>\/?]+(.)*[^!@#$%\^&\*\(\)_\+\-=\[\]{};':"\\|,.<>\/?]+@(.)+\.(.)+$/;
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
            return [true, providedName.replace(invalidRegex1, "")];
        }
        return [true, providedName];
    } else if (invalidRegex1.test(providedName)) {
        return [true, providedName.replace(invalidRegex1, "")];
    }

    return [false, providedName];
}

module.exports = {
    searchUser, createUser, deleteUsers, formatUsername
}
