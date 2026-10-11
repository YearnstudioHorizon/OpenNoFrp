package panel

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"opennofrp/pkg/protocol"
)

func (p *Panel) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := p.Store.GetClient(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	back := "/clients/" + id
	online, _, caps := p.clientStatus(c)
	if !online {
		http.Redirect(w, r, back+"?err="+url.QueryEscape("机器离线，暂时无法更新 Client"), http.StatusSeeOther)
		return
	}
	if p.UpdateClient == nil || !protocol.HasCapability(caps, protocol.CapSelfUpdate) {
		http.Redirect(w, r, back+"?err="+url.QueryEscape("该客户端尚不支持远程更新，请先在机器上手动升级一次"), http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	message, err := p.UpdateClient(ctx, id)
	if err != nil {
		message = err.Error()
		runes := []rune(message)
		if len(runes) > 512 {
			message = string(runes[:512]) + "…"
		}
		http.Redirect(w, r, back+"?err="+url.QueryEscape(message), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, back+"?ok="+url.QueryEscape(message), http.StatusSeeOther)
}
