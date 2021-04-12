const express = require("express");
const fs = require("fs");
const https = require("https");

const PORT = "4000";

async function startServer() {
  const app = express();

  await require("./app/index").default({ expressApp: app });

  https
    .createServer(
      {
        key: fs.readFileSync("./security/key.pem"),
        cert: fs.readFileSync("./security/cert.pem"),
        passphrase: "mihiru",
        rejectUnauthorized: false,
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
