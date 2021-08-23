postgres:
	docker run --name postgres12 -p 5432:5432 -e POSTGRES_USER=root -e POSTGRES_PASSWORD=secret -d postgres:12-alpine

createdb:
	docker exec -it postgres12 createdb --username=root	--owner=root test-ub

dropdb:
	docker exec -it postgres12 dropdb test-ub

migrateup:
	migrate -path repository/migration -database "postgresql://root:secret@localhost:5432/test-ub?sslmode=disable" -verbose up

migratedown:
	migrate -path repository/migration -database "postgresql://root:secret@localhost:5432/test-ub?sslmode=disable" -verbose down

test:
	go test -cover ./...

mock-protocol:
	mockgen -package tests -destination ./tests/mock_protocol.go github.com/ubirch/ubirch-cose-client-go/main/repository Protocols


.PHONY: postgres createdb dropdb migrateup migratedown sqlc test mock-protocol