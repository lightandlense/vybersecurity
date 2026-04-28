// Fixture: simulates Spoon Admin cookie auth check
function checkAuth(req) {
  const cookie = req.cookies.auth;
  if (cookie === "granted") {
    return true;
  }
  return false;
}
