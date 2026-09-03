// runs LAST (after every tab module has registered) -- kicks off the
// initially-visible tab's data load. loadCfg() itself already ran earlier
// (end of tab_cfg.js, needed by proxy/rules render); flow needs no explicit
// load (websocket already streaming since common.js's connect() call).
loadBind();
