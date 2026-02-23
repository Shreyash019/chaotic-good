package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/graphql-go/graphql"
	jschema "github.com/shreyashkumar/funny-pipe/services/joke/internal/schema"
)

// GraphQLHandler handles POST (query execution) and GET (GraphiQL explorer) at /graphql.
type GraphQLHandler struct {
	schema graphql.Schema
}

func NewGraphQLHandler(s graphql.Schema) *GraphQLHandler {
	return &GraphQLHandler{schema: s}
}

type gqlRequest struct {
	Query         string         `json:"query"`
	Variables     map[string]any `json:"variables"`
	OperationName string         `json:"operationName"`
}

func (h *GraphQLHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.serveGraphiQL(w, r)
	case http.MethodPost:
		h.executeQuery(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *GraphQLHandler) executeQuery(w http.ResponseWriter, r *http.Request) {
	var req gqlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	// Inject the authenticated user ID forwarded by the gateway
	userID := r.Header.Get("X-User-ID")
	ctx := context.WithValue(r.Context(), jschema.UserIDKey, userID)

	result := graphql.Do(graphql.Params{
		Schema:         h.schema,
		RequestString:  req.Query,
		VariableValues: req.Variables,
		OperationName:  req.OperationName,
		Context:        ctx,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // GraphQL always returns 200; errors live in result.Errors
	json.NewEncoder(w).Encode(result)
}

func (h *GraphQLHandler) serveGraphiQL(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, graphiQLPage)
}

// graphiQLPage is a minimal GraphiQL explorer loaded from CDN.
const graphiQLPage = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Joke Service — GraphiQL</title>
  <link rel="stylesheet" href="https://unpkg.com/graphiql@3/graphiql.min.css" />
</head>
<body style="margin:0">
  <div id="graphiql" style="height:100vh"></div>
  <script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
  <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
  <script crossorigin src="https://unpkg.com/graphiql@3/graphiql.min.js"></script>
  <script>
    const token = localStorage.getItem('access_token') || '';
    const fetcher = GraphiQL.createFetcher({
      url: window.location.pathname,
      headers: token ? { 'Authorization': 'Bearer ' + token } : {},
    });
    ReactDOM.createRoot(document.getElementById('graphiql')).render(
      React.createElement(GraphiQL, {
        fetcher,
        defaultEditorToolsVisibility: true,
        defaultQuery: [
          '# Tip: set your access_token in localStorage for auth mutations',
          '# localStorage.setItem("access_token", "<your_token>")',
          '',
          '# --- Queries ---',
          'query ListJokes {',
          '  jokes(limit: 10) { id content category createdAt }',
          '}',
          '',
          '# --- Mutations ---',
          '# mutation CreateJoke {',
          '#   createJoke(content: "Why did the gopher fail? It ran out of channels.", category: "tech") {',
          '#     id content category',
          '#   }',
          '# }',
        ].join('\n'),
      })
    );
  </script>
</body>
</html>`
