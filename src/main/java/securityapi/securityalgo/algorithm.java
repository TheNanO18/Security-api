package securityapi.securityalgo;

public interface algorithm {
    byte[] process(byte[] data, byte[] key, byte[] iv, boolean encryptMode);

    String getName();
}