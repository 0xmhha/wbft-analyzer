package api

import "net/http"

func (s *Server) followState(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookupDataset(w, r, "follow")
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		writeError(w, 400, "follow state does not accept filters")
		return
	}
	data, e := s.Store.FollowState(r.Context(), d.ID)
	if e != nil {
		s.fail(w, r, e)
		return
	}
	writeJSON(w, 200, data)
}
