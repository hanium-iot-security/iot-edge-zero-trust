import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";
import axios from "axios";
import { transformWithOxc } from "vite";

const source = await readFile(new URL("./api.js", import.meta.url), "utf8");
const { code } = await transformWithOxc(
  source.replace(/^import\b[\s\S]*?;\r?\n/gm, ""),
  "api.js",
  { define: { "import.meta.env": "{}" } },
);

// Regression: ISSUE-003 — management failures exposed backend auth codes.
// Found by dashboard browser QA on 2026-10-31.
// Execute the production API module with real Axios; only its HTTP adapter is a fixture.
function rejectedApi(status, data, errorCode = "ERR_BAD_REQUEST") {
  const requests = [];
  const transport = axios.create({
    adapter: async (config) => {
      requests.push(config);
      throw new axios.AxiosError("Request failed", errorCode, config, undefined, {
        status, data, config, headers: {},
      });
    },
  });
  transport.isCancel = axios.isCancel;
  const scope = { axios: transport, mockSummary: {}, Error };
  runInNewContext(
    code.replace(/\bexport\s+(?=(?:async\s+)?function\b)/g, "")
      .replace(/\bexport\s*\{[^}]*\};?/g, "") +
      "\nglobalThis.api = { createDevice, getSummary };",
    scope,
  );
  return { ...scope.api, requests };
}

test("registration with a rejected admin key explains the failure and preserves diagnostics", async () => {
  const body = { detail: "RECOVERY_ADMIN_UNAUTHORIZED" };
  const api = rejectedApi(401, body);
  await assert.rejects(api.createDevice({ device_id: "fixture-device" }, "test-only-key"), (error) => {
    assert.equal(error.message, "관리자 인증에 실패했습니다. 입력한 관리자 인증키를 확인해 주세요.");
    assert.equal(error.status, 401);
    assert.equal(error.code, "ERR_BAD_REQUEST");
    assert.equal(error.responseData, body);
    assert.equal(error.isCanceled, false);
    return true;
  });
  assert.equal(api.requests.length, 1);
  assert.equal(api.requests[0].method, "post");
  assert.equal(api.requests[0].url.endsWith("/devices"), true);
});

test("an unconfigured server admin key explains the required server setting", async () => {
  const body = { detail: "RECOVERY_ADMIN_NOT_CONFIGURED" };
  const api = rejectedApi(503, body, "ERR_BAD_RESPONSE");
  await assert.rejects(api.createDevice({ device_id: "fixture-device" }, "test-only-key"), (error) => {
    assert.equal(error.message, "서버에 관리자 인증키가 설정되지 않아 관리자 기능을 사용할 수 없습니다. 서버 설정을 확인해 주세요.");
    assert.equal(error.status, 503);
    assert.equal(error.code, "ERR_BAD_RESPONSE");
    assert.equal(error.responseData, body);
    return true;
  });
});

test("GET requests use the same auth explanation without losing the backend detail", async () => {
  const body = { detail: "RECOVERY_ADMIN_UNAUTHORIZED" };
  const api = rejectedApi(401, body);
  await assert.rejects(api.getSummary(), (error) => {
    assert.equal(error.message, "관리자 인증에 실패했습니다. 입력한 관리자 인증키를 확인해 주세요.");
    assert.equal(error.responseData, body);
    return true;
  });
  assert.equal(api.requests[0].method, "get");
});

test("auth-like text on other statuses and unrelated failures retain their original meanings", async () => {
  for (const [status, detail] of [
    [403, "RECOVERY_ADMIN_UNAUTHORIZED"],
    [503, "RECOVERY_ADMIN_UNAUTHORIZED"],
    [401, "RECOVERY_ADMIN_NOT_CONFIGURED"],
    [503, "CAPTURE_NOT_READY"],
    [401, "ACCOUNT_LOCKED"],
  ]) {
    const body = { detail };
    const api = rejectedApi(status, body);
    await assert.rejects(api.getSummary(), (error) => {
      assert.equal(error.message, detail);
      assert.equal(error.status, status);
      assert.equal(error.responseData, body);
      return true;
    });
  }
});

test("structured recovery failure codes remain available to uncertain-outcome handling", async () => {
  const body = { detail: { failure_code: "BASELINE_RECOVERY_COMMITTED_UNVERIFIED", message: "Verification pending" } };
  const api = rejectedApi(503, body, "ERR_BAD_RESPONSE");
  await assert.rejects(api.getSummary(), (error) => {
    assert.equal(error.message, "Verification pending");
    assert.equal(error.responseData, body);
    assert.equal(error.responseData.detail.failure_code, "BASELINE_RECOVERY_COMMITTED_UNVERIFIED");
    return true;
  });
});

test("status fallback messages still apply when the server provides no detail", async () => {
  for (const [status, message] of [
    [401, "관리자 인증에 실패했습니다."],
    [403, "요청을 수행할 권한이 없습니다."],
    [503, "관리자 기능을 사용할 수 없습니다."],
  ]) {
    const api = rejectedApi(status, {});
    await assert.rejects(api.getSummary(), (error) => error.message === message);
  }
});
