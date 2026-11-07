package org.example.spakeepalive;
final class NativeSpa {
    static { System.loadLibrary("spa"); }
    static native String encode(String message, String username, int timeout, byte[] key, byte[] hmac);
}
