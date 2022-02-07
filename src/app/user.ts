import axios from "axios";
const fs = require("fs");
const readline = require("readline");

let config = require("./../../config.json");

/**
 * Find availability of a user with SCIM2 API
 */
const searchUser = async (req) => {
    // Set filter for user search
    var filter = `userName sw ${req.body.username}`;

    var searchUserdata = {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
        attributes: ["name.familyName", "userName"],
        filter: filter,
        domain: "PRIMARY",
        startIndex: 1,
        count: 100,
    };

    return await axios({
        method: "post",

        url: `https://${config.host}:9443/scim2/Users/.search`,
        headers: {
            "Content-Type": "application/scim+json",
            Authorization: "Basic YWRtaW46YWRtaW4=",
        },
        data: searchUserdata,
    });
};

/**
 * Create user with SCIM2 API
 */
const createUser = async (userData) => {
    var data = JSON.stringify({
        schemas: [],
        name: {
            // familyName: userData.familyName,
            // givenName: userData.givenName,
            formatted: userData.givenName + " " + userData.familyName,
        },
        displayName: userData.givenName + " " + userData.familyName,
        userName: userData.userName,
        password: userData.password,
        emails: [{
                primary: true,
                value: userData.homeEmail,
                type: "home"
            },
            {
                value: userData.workEmail,
                type: "work"
            },
        ],
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            customClaim: userData.attestationClaim,
        },
    });

    var userCreated = false;

    try {
        // console.log(data);
        await axios({
            method: "post",
            url: `https://${config.host}:9443/scim2/Users`,
            headers: {
                "Content-Type": "application/json",
                Authorization: "Basic YWRtaW46YWRtaW4=",
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

    var userCount = 0;
    var deletedCount = 0;

    for await (const userId of readLine) {
        userCount += 1;
        try {
            await axios({
                method: "delete",
                url: `https://${config.host}:9443/scim2/Users/${userId}`,
                headers: {
                    "Content-Type": "application/json",
                    Authorization: "Basic YWRtaW46YWRtaW4=",
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

/**
 * Create user claim
 */
const createClaim = async (claimData) => {
    var data = JSON.stringify({
        claimURI: "http://wso2.org/claims/a",
        description: "Some description about the claim.",
        displayOrder: 10,
        displayName: "Test",
        readOnly: false,
        required: false,
        supportedByDefault: true,
        attributeMapping: [{
            mappedAttribute: "username",
            userstore: "PRIMARY"
        }],
        properties: [{
            key: "string",
            value: "string"
        }],
    });

    try {
        return await axios({
            method: "post",
            url: `https://${config.host}:9443/api/server/v1/claim-dialects/local/claims`,
            headers: {
                accept: "application/json",
                "Content-Type": "application/json",
                Authorization: "Basic YWRtaW46YWRtaW4=",
            },
            data: data,
        });
    } catch (error) {
        console.error(error);
    }
};

/**
 * Set user claim
 */
const setClaim = async (claimData) => {
    var data = JSON.stringify({
        claimURI: "http://wso2.org/claims/username",
        description: "Some description about the claim.",
        displayOrder: 10,
        displayName: "Username",
        readOnly: true,
        regEx: "^([a-zA-Z)$",
        required: true,
        supportedByDefault: true,
        attributeMapping: [{
            mappedAttribute: "username",
            userstore: "SECONDARY"
        }],
        properties: [{
            key: "string",
            value: "string"
        }],
    });

    try {
        return await axios({
            method: "put",
            url: "https://localhost:9443/api/server/v1/claim-dialects/local/claims/test",
            headers: {
                accept: "application/json",
                "Content-Type": "application/json",
            },
            data: data,
        });
    } catch (error) {
        console.error(error);
    }
};

module.exports = {
    searchUser, createUser, deleteUsers, createClaim, setClaim
}
