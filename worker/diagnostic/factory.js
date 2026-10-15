import { createHandler } from "../src/handler.js";
import { scopedRuntime } from "./runtime.js";

export function createDiagnosticHandler(native, emit) {
  // createHandler runs ONCE, so its original isolate-wide admission limit is
  // shared by all requests. Only each request's runtime is scoped by the build.
  return createHandler({ forRequest: (request, env) => scopedRuntime(native, request, env, emit) });
}
