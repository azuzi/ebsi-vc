import express from "express";
import { verifyvc,createvc } from "./router/vc.router";

const app = express();
const PORT = 9080;
app.use(express.json());
app.use("/1.0/verify", verifyvc);
app.use("/1.0/create", createvc);

app.get("/", (req, res) => res.send("Express + TypeScript Server"));
app.listen(PORT, () => {
  console.log(`⚡️[server]: Server is running at https://localhost:${PORT}`);
});
