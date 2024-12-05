package cipher

func incrementNonce(b []byte) {
    for i := range b {
        b[i]++
        if b[i] != 0 {
            return
        }
    }
} 