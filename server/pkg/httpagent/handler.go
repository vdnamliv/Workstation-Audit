package httpagent

import (
    "encoding/json"
    "net/http"

    "vt-audit/server/pkg/model"
    "vt-audit/server/pkg/policy"
    "vt-audit/server/pkg/storage"
)

type Server struct {
    Store  storage.Store
    Cfg    model.Config

    // cached active policy for quick healthchecks
    active *model.ActivePolicy
}

func New(store storage.Store, cfg model.Config) (*Server, error) {
    ap, err := store.LoadActivePolicy("windows")
    if err != nil { return nil, err }
    return &Server{Store: store, Cfg: cfg, active: ap}, nil
}

func (s *Server) routes(mux *http.ServeMux, prefix string) {
    // helper to add optional prefix without duplicate slashes
    p := func(path string) string {
        if prefix == "" || prefix == "/" { return path }
        if path == "/" { return prefix }
        if prefix[len(prefix)-1] == '/' { return prefix[:len(prefix)-1] + path }
        return prefix + path
    }
    mux.HandleFunc(p("/enroll"), s.handleEnroll)
    mux.HandleFunc(p("/policies"), s.handlePoliciesCompat)
    mux.HandleFunc(p("/policy/enroll"), s.handlePolicyEnroll)
    mux.HandleFunc(p("/policy/healthcheck"), s.handlePolicyHealth)
    mux.HandleFunc(p("/results"), s.handleResults)
}

func (s *Server) Handler() http.Handler {
    mux := http.NewServeMux()
    s.routes(mux, "")
    return mux
}

// Mount registers agent routes onto an external mux with an optional prefix.
func (s *Server) Mount(mux *http.ServeMux, prefix string) { s.routes(mux, prefix) }

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost { http.Error(w, "method", http.StatusMethodNotAllowed); return }
    var in struct {
        EnrollmentKey string `json:"enrollment_key"`
        Hostname      string `json:"hostname"`
        OS            string `json:"os"`
        Arch          string `json:"arch"`
        Version       string `json:"version"`
        Fingerprint   string `json:"fingerprint"`
    }
    if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
        http.Error(w, "bad json", http.StatusBadRequest); return
    }
    if in.EnrollmentKey != "ORG_KEY_DEMO" {
        http.Error(w, "bad enrollment key", http.StatusForbidden); return
    }
    aid, sec, err := s.Store.UpsertAgent(in.Hostname, in.OS, in.Fingerprint)
    if err != nil { http.Error(w, "db error", http.StatusInternalServerError); return }
    _ = json.NewEncoder(w).Encode(map[string]any{
        "agent_id": aid, "agent_secret": sec, "poll_interval_sec": 30,
    })
}

// Legacy route used by older agent builds to fetch full policy blob.
func (s *Server) handlePoliciesCompat(w http.ResponseWriter, r *http.Request) {
    if _, _, ok := s.Store.AuthAgent(r); !ok { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
    if s.active == nil { http.Error(w, "no policy", http.StatusNotFound); return }
    var tmp struct {
        Version  int                      `json:"version"`
        Policies []map[string]interface{} `json:"policies"`
    }
    _ = json.Unmarshal(s.active.Config, &tmp)
    _ = json.NewEncoder(w).Encode(tmp)
}

func (s *Server) handlePolicyEnroll(w http.ResponseWriter, r *http.Request) {
    ap, _ := s.Store.LoadActivePolicy("windows")
    if ap != nil { s.active = ap }
    if s.active == nil { http.Error(w, "no policy", http.StatusNotFound); return }
    _ = json.NewEncoder(w).Encode(map[string]any{
        "policy_id": s.active.PolicyID,
        "version":   s.active.Version,
        "hash":      s.active.Hash,
        "config":    json.RawMessage(s.active.Config),
    })
}

func (s *Server) handlePolicyHealth(w http.ResponseWriter, r *http.Request) {
    var req struct {
        OS       string `json:"os"`
        PolicyID string `json:"policy_id"`
        Version  int    `json:"version"`
        Hash     string `json:"hash"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "bad json", http.StatusBadRequest); return
    }
    ap, _ := s.Store.LoadActivePolicy("windows")
    if ap == nil { http.Error(w, "no policy", http.StatusNotFound); return }
    s.active = ap
    if req.PolicyID == s.active.PolicyID && req.Version == s.active.Version && req.Hash == s.active.Hash {
        _ = json.NewEncoder(w).Encode(map[string]any{"status":"ok"})
        return
    }
    _ = json.NewEncoder(w).Encode(map[string]any{
        "status":"update",
        "policy": map[string]any{
            "policy_id": s.active.PolicyID,
            "version":   s.active.Version,
            "hash":      s.active.Hash,
            "config":    json.RawMessage(s.active.Config),
        },
    })
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
    aid, _, ok := s.Store.AuthAgent(r)
    if !ok { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
    var payload model.ResultsPayload
    if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
        http.Error(w, "bad json", http.StatusBadRequest); return
    }
    if err := s.Store.ReplaceLatestResults(aid, payload); err != nil {
        http.Error(w, "db error", http.StatusInternalServerError); return
    }
    _ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "stored": len(payload.Results)})
}

// Utilities exposed for other modules that need to seed policies.
func SeedIfEmpty(st storage.Store, rulesDir string) (*model.ActivePolicy, error) {
    ap, err := st.LoadActivePolicy("windows")
    if err != nil { return nil, err }
    if ap != nil { return ap, nil }
    rules, err := policy.LoadWindowsPolicies(rulesDir)
    if err != nil { return nil, err }
    policy.NormalizePolicies(rules)
    cfgBlob, _ := json.Marshal(struct {
        Version  int                      `json:"version"`
        Policies []map[string]interface{} `json:"policies"`
    }{Version: 1, Policies: rules})
    hash := policy.JSONHash(cfgBlob)
    if err := st.InsertPolicyVersion("win_baseline", "windows", 1, cfgBlob, hash, string(policy.MustYAML(rules)));
        err != nil { return nil, err }
    if err := st.SetActivePolicy("windows", "win_baseline", 1); err != nil { return nil, err }
    return st.LoadActivePolicy("windows")
}
