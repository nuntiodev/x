package hashx

type Hashx interface {
	CreateHash(code string) (string, error)
	CompareHashCode(hash, code string) error
}
