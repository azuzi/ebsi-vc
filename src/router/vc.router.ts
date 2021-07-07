import express, { Request, Response } from "express";

import { verifyVC, createVC } from "../vc";
export const verifyvc = express.Router();

verifyvc.post("/", async (req: Request, res: Response) => {
  try {
    const response = await verifyVC();
    try {
      res.sendStatus(200);
    } catch (e) {
      res.sendStatus(500);
    }
  } catch (error) {
    res.sendStatus(500);
  }
});

export const createvc = express.Router();

createvc.post("/", async (req: Request, res: Response) => {
  try {
    const response = await createVC();
    try {
      res.sendStatus(200);
    } catch (e) {
      res.sendStatus(500);
    }
  } catch (error) {
    res.sendStatus(500);
  }
});