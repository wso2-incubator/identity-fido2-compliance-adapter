import express, { response } from "express";
const path = require("path");

export default ({ app }: { app: express.Application }) => {
    app.get("/interop-webapp", (req, res) => {
      res.sendFile(path.join(__dirname, 'index.html'));
    });
}
