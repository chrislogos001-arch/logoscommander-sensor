// Copies the bench page and the sensor module into dist/ for static hosting.
import { cpSync, mkdirSync, rmSync } from "node:fs";
const root = new URL("..", import.meta.url).pathname;
rmSync(root + "dist", { recursive: true, force: true });
mkdirSync(root + "dist");
for (const f of ["index.html", "bench.js", "bench.css", "_headers"]) cpSync(root + "bench/" + f, root + "dist/" + f);
cpSync(root + "sensor/sensor.js", root + "dist/sensor.js");
console.log("built dist/");
