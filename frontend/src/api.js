// Every call to the backend goes through api(). The session cookie is sent
// automatically by the browser; JavaScript never sees it (it is httpOnly).

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

// FastAPI errors look like {"detail": "text"} or, for invalid input,
// {"detail": [{"loc": [...], "msg": "..."}]}.
function errorMessage(data, status) {
  const detail = data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((item) => item.msg).join("; ");
  return `Request failed (${status})`;
}

export async function api(path, { method = "GET", body, form } = {}) {
  const options = { method, headers: {} };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  } else if (form) {
    options.body = form; // FormData: the browser sets the multipart Content-Type itself
  }
  const response = await fetch(path, options);
  const isJson = response.headers.get("content-type")?.includes("application/json");
  const data = isJson ? await response.json() : null;
  if (!response.ok) throw new ApiError(errorMessage(data, response.status), response.status);
  return data;
}
