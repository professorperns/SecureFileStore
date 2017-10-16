package proj2

import (
	"testing"
	"time"

	"github.com/nweaver/cs161-p2/userlib"
)

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	DebugPrint = false
	someUsefulThings()
	userlib.DatastoreClear()
	DebugPrint = true
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	// And some more tests, because
	DebugPrint = true
	v, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", v)
}

func Test2(t *testing.T) {
	// Having previously created a user "alice" with password "fubar"...
	DebugPrint = true
	alice, _ := GetUser("alice", "fubar")
	also_alice, _ := GetUser("alice", "fubar")
	debugMsg("Done loading users")
	debugMsg("Storing file")
	alice.StoreFile("todo", []byte("write tests"))
	todo, _ := also_alice.LoadFile("todo")
	if string(todo) != "write tests" {
		t.Error("Same user and password could not access file: ", todo)
	}
}

func TestEncryption(t *testing.T) {
	DebugPrint = true
	alice, _ := GetUser("alice", "fubar")
	alice.StoreFile("foo", []byte("this message should not be the same"))
	alice.StoreFile("bar", []byte("this message should not be the same"))
	access_foo := GenerateHMAC(alice.HMACKey, []byte("alice"+"fubar"+"foo"))
	access_bar := GenerateHMAC(alice.HMACKey, []byte("alice"+"fubar"+"bar"))
	foo, _ := userlib.DatastoreGet(string(access_foo))
	bar, _ := userlib.DatastoreGet(string(access_bar))
	debugMsg("Ciphertext of foo: %x", foo)
	debugMsg("Ciphertext of bar: %x", bar)
	if userlib.Equal(foo, bar) {
		t.Error("Ciphertext of the same plaintext is the same")
	}
}

func TestAppend(t *testing.T) {
	DebugPrint = false
	appends := [][]byte{[]byte("this"), []byte("love"), []byte("has"), []byte("taken"), []byte("its"), []byte("toll"),
		[]byte("on"), []byte("me,"), []byte("she"), []byte("said"), []byte("goodbye"),
		[]byte("too"), []byte("many"), []byte("times"), []byte("before")}
	alice, _ := GetUser("alice", "fubar")
	alice.StoreFile("maroon5", []byte(""))
	for _, v := range appends {
		debugMsg("Word: %v", string(v))
		alice.AppendFile("maroon5", v)
		debugMsg("Space")
		alice.AppendFile("maroon5", []byte(" "))
	}
	lyrics, _ := alice.LoadFile("maroon5")
	debugMsg("Song Lyrics: %s", lyrics)
}

func TestAppendPerfomance(t *testing.T) {
	DebugPrint = true
	alice, _ := GetUser("alice", "fubar")
	alice.StoreFile("append_performance", []byte(""))
	repetitions := []uint{10, 100, 1000}
	for _, v := range repetitions {
		start := time.Now()
		for i := uint(0); i < v; i++ {
			alice.AppendFile("append_performance", []byte("foo"))
		}
		t := time.Now()
		diff := t.Sub(start)
		debugMsg("Time for %i repetitions: %i", v, diff.Seconds())
	}
}

func TestShareFile(t *testing.T) {

}
