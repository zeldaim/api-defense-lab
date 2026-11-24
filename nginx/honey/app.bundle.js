// restaurant web client (lab) — the "_internal" block is a decoy: no real client ever calls it.
// Any request to /internal/* means the caller parsed this bundle for API paths (automated harvesting).
const API = {
  menu: "/menu", orders: "/orders", profile: "/profile", token: "/token",
  _internal: {
    exportOrders: "/internal/v2/orders/export",
    debugConfig: "/internal/debug/config",
    adminUsers: "/internal/admin/users",
  },
};
export default API;
