import bodyParser from "body-parser";
import cors from "cors";

const fs = require("fs");
const https = require("https");
const express = require("express");

const PORT = "4000";

async function startServer() {
    const app = express();

    app.use(cors());
    app.use(bodyParser.json());

    await require("./app/index").default({ expressApp: app });

    https
        .createServer(
            {
                cert: fs.readFileSync("./security/server.cert"),
                key: fs.readFileSync("./security/server.key")
            },
            app
        )
        .listen(PORT, (err: any) => {
            if (err) {
                process.exit(1);
            }
            console.log(`Server listening on port: ${PORT}`);
        });
}

startServer();
