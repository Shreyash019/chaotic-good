// Package schema defines the GraphQL schema for the joke service.
package schema

import (
	"errors"
	"time"

	"github.com/graphql-go/graphql"
	"github.com/Shreyash019/chaotic-good/services/joke/internal/model"
	"github.com/Shreyash019/chaotic-good/services/joke/internal/repository"
)

// ContextKey is the type used for context values set by the HTTP handler.
type ContextKey string

// UserIDKey is used to store/retrieve the authenticated user's ID from context.
const UserIDKey ContextKey = "userID"

// jokeType is the GraphQL object type for a Joke.
var jokeType = graphql.NewObject(graphql.ObjectConfig{
	Name:        "Joke",
	Description: "A joke submitted by a user",
	Fields: graphql.Fields{
		"id":        &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
		"userId":    &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
		"content":   &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
		"category":  &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
		"createdAt": &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
	},
})

// jokeToMap converts a model.Joke to a map so graphql-go can resolve field names correctly.
func jokeToMap(j *model.Joke) map[string]interface{} {
	if j == nil {
		return nil
	}
	return map[string]interface{}{
		"id":        j.ID,
		"userId":    j.UserID,
		"content":   j.Content,
		"category":  j.Category,
		"createdAt": j.CreatedAt.Format(time.RFC3339),
	}
}

func jokesToMaps(jokes []*model.Joke) []interface{} {
	result := make([]interface{}, len(jokes))
	for i, j := range jokes {
		result[i] = jokeToMap(j)
	}
	return result
}

// Build constructs and returns the GraphQL schema wired to the given repository.
func Build(repo repository.IJokeRepository) (graphql.Schema, error) {
	queryType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			// jokes(category: String, limit: Int): [Joke!]!
			"jokes": &graphql.Field{
				Type:        graphql.NewNonNull(graphql.NewList(graphql.NewNonNull(jokeType))),
				Description: "List jokes, optionally filtered by category",
				Args: graphql.FieldConfigArgument{
					"category": &graphql.ArgumentConfig{Type: graphql.String, Description: "Filter by category"},
					"limit":    &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 20, Description: "Max results (default 20)"},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					category, _ := p.Args["category"].(string)
					limit, _ := p.Args["limit"].(int)
					jokes, err := repo.List(category, limit)
					if err != nil {
						return nil, err
					}
					return jokesToMaps(jokes), nil
				},
			},

			// joke(id: ID!): Joke
			"joke": &graphql.Field{
				Type:        jokeType,
				Description: "Fetch a single joke by ID",
				Args: graphql.FieldConfigArgument{
					"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					id, _ := p.Args["id"].(string)
					j, err := repo.GetByID(id)
					if err != nil {
						return nil, err
					}
					return jokeToMap(j), nil
				},
			},

			// randomJoke(category: String): Joke
			"randomJoke": &graphql.Field{
				Type:        jokeType,
				Description: "Fetch a random joke, optionally filtered by category",
				Args: graphql.FieldConfigArgument{
					"category": &graphql.ArgumentConfig{Type: graphql.String},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					category, _ := p.Args["category"].(string)
					j, err := repo.Random(category)
					if err != nil {
						return nil, err
					}
					return jokeToMap(j), nil
				},
			},
		},
	})

	mutationType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Mutation",
		Fields: graphql.Fields{
			// createJoke(content: String!, category: String): Joke!
			"createJoke": &graphql.Field{
				Type:        graphql.NewNonNull(jokeType),
				Description: "Create a new joke (requires authentication)",
				Args: graphql.FieldConfigArgument{
					"content":  &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"category": &graphql.ArgumentConfig{Type: graphql.String, DefaultValue: "general"},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, _ := p.Context.Value(UserIDKey).(string)
					if userID == "" {
						return nil, errors.New("unauthorized")
					}
					content, _ := p.Args["content"].(string)
					category, _ := p.Args["category"].(string)
					if category == "" {
						category = "general"
					}
					j, err := repo.Create(userID, &model.CreateJokeInput{
						Content:  content,
						Category: category,
					})
					if err != nil {
						return nil, err
					}
					return jokeToMap(j), nil
				},
			},

			// deleteJoke(id: ID!): Boolean!
			"deleteJoke": &graphql.Field{
				Type:        graphql.NewNonNull(graphql.Boolean),
				Description: "Delete a joke you own",
				Args: graphql.FieldConfigArgument{
					"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, _ := p.Context.Value(UserIDKey).(string)
					if userID == "" {
						return false, errors.New("unauthorized")
					}
					id, _ := p.Args["id"].(string)
					if err := repo.Delete(id, userID); err != nil {
						return false, err
					}
					return true, nil
				},
			},
		},
	})

	return graphql.NewSchema(graphql.SchemaConfig{
		Query:    queryType,
		Mutation: mutationType,
	})
}
