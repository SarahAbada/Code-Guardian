import { Router, type IRouter } from "express";
import healthRouter from "./health";
import auditRouter from "./audit";
import tokensRouter from "./tokens";
import auditCliRouter from "./auditCli";

const router: IRouter = Router();

router.use(healthRouter);
router.use(auditRouter);
router.use(tokensRouter);
router.use(auditCliRouter);

export default router;
