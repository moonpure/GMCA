import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

public class GMCA {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // TestEncryptDecrypt();//测试加解密，公私钥用base64转换
        // genGMCACert();
        //TestCipherEncryptDecrypt();
        tetsGudongall();
//        genGMCACert();
//       genCertWithCaSign();
//        testDigitalSign();
//        testSaveGMKeyStore();
    }

    public static void genGMCACert() throws Exception {
        //自签
        System.out.println("=============测试生成国密CA根证书=============");
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");

        g.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));

        KeyPair p = g.generateKeyPair();

        PrivateKey privKey = p.getPrivate();
        PublicKey pubKey = p.getPublic();
        byte[] pubByte = pubKey.getEncoded();
        byte[] privateByte = privKey.getEncoded();
        System.out.println("CA PrivateKey:" + Base64.toBase64String(privKey.getEncoded()));

        X500Principal iss = new X500Principal("CN=G4B GM ROOT CA,OU=g4b,C=CN,S=Guangdong,O=g4b");

        ContentSigner sigGen = new JcaContentSignerBuilder("SM3withSM2").setProvider("BC").build(privKey);

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                iss,
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis() - 50000),
                new Date(System.currentTimeMillis() + 50000),
                iss,
                pubKey).addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                new X509KeyUsage(0xfe))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                        new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
                        new GeneralNames(new GeneralName[]
                                {
                                        new GeneralName(GeneralName.rfc822Name, "gmca@g4b.cn"),
                                        new GeneralName(GeneralName.dNSName, "ca.g4b.cn")
                                }));


        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));


        String info = null;
        //获得证书版本
        info = String.valueOf(cert.getVersion());
        System.out.println("证书版本:" + info);
        //获得证书序列号
        info = cert.getSerialNumber().toString(16);
        System.out.println("证书序列号:" + info);
        //获得证书有效期
        Date beforedate = cert.getNotBefore();
        info = beforedate.toString();
        System.out.println("证书生效日期:" + info);
        Date afterdate = cert.getNotAfter();
        info = beforedate.toString();
        System.out.println("证书失效日期:" + info);
        //获得证书主体信息
        info = cert.getSubjectDN().getName();
        System.out.println("证书拥有者:" + info);
        //获得证书颁发者信息
        info = cert.getIssuerDN().getName();
        System.out.println("证书颁发者:" + info);
        //获得证书签名算法名称
        info = cert.getSigAlgName();
        System.out.println("证书签名算法:" + info);


        byte[] byt = cert.getExtensionValue("2.5.29.15");
        String strExt = new String(byt);
        System.out.println("证书扩展域:" + strExt);
        byt = cert.getExtensionValue("2.5.29.37");
        strExt = new String(byt);
        System.out.println("证书扩展域2:" + strExt);
        byt = cert.getExtensionValue("2.5.29.17");
        strExt = new String(byt);
        System.out.println("证书扩展域2:" + strExt);

        cert.checkValidity(new Date());

        cert.verify(pubKey);


        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

        cert = (X509Certificate) fact.generateCertificate(bIn);

        System.out.println("CA Cert:" + Base64.toBase64String(cert.getEncoded()));

        saveFile("CAPrikey", privKey.getEncoded());
        saveFile("CARootCert.cer", cert.getEncoded());
        System.out.println("=============测试生成国密CA根证书=============");
    }


    public static void genCertWithCaSign() throws Exception {
        //用ca签
        System.out.println("=============测试国密CA根证书签发国密证书=============");
        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(readFile("CAPrikey"));

        PrivateKey caPrivateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509", "BC");

        Certificate caRootCert = certificateFactory.generateCertificate(new FileInputStream("CARootCert.cer"));

        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");

        g.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));

        KeyPair p = g.generateKeyPair();

        PrivateKey privKey = p.getPrivate();
        PublicKey pubKey = p.getPublic();


        ContentSigner sigGen = new JcaContentSignerBuilder("SM3withSM2").setProvider("BC").build(caPrivateKey);

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                (X509Certificate) caRootCert,
                BigInteger.valueOf(new Random().nextInt()),
                new Date(System.currentTimeMillis() - 50000),
                new Date(System.currentTimeMillis() + 50000),
                new X500Principal("CN=g4bTestCert"),
                pubKey).addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                        new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
                        new GeneralNames(new GeneralName[]
                                {
                                        new GeneralName(GeneralName.rfc822Name, "gmca@g4b.cn"),
                                        new GeneralName(GeneralName.dNSName, "ca.g4b.cn")
                                }));


        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));


        cert.checkValidity(new Date());

        cert.verify(caRootCert.getPublicKey());

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

        cert = (X509Certificate) fact.generateCertificate(bIn);

        System.out.println("custCert:" + Base64.toBase64String(cert.getEncoded()));
        System.out.println("custPrivateKey:" + Base64.toBase64String(privKey.getEncoded()));
        saveFile("custCert.cer", cert.getEncoded());
        saveFile("custPrivateKey", privKey.getEncoded());
        System.out.println("=============测试国密CA根证书签发国密证书=============");

    }

    public static void testDigitalSign() throws Exception {
        System.out.println("=============测试国密证书数字签名=============");
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(readFile("custPrivateKey"));

        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509", "BC");

        Certificate certificate = certificateFactory.generateCertificate(new FileInputStream("custCert.cer"));

        Signature signature = Signature.getInstance("SM3withSM2", "BC");

        signature.initSign(privateKey);

        String signText = "测试123456test";
        signature.update(signText.getBytes("UTF-8"));

        byte[] digitalsignature = signature.sign();

        System.out.println("signText:" + signText);

        System.out.println("digitalsignature:" + Base64.toBase64String(digitalsignature));

        Signature signature1 = Signature.getInstance("SM3withSM2", "BC");

        signature1.initVerify(certificate.getPublicKey());

        signature1.update(signText.getBytes("UTF-8"));

        boolean result = signature1.verify(digitalsignature);

        System.out.println("verifyResult:" + result);


        Signature signature2 = Signature.getInstance("SM3withSM2", "BC");

        signature2.initVerify(certificate.getPublicKey());

        signature2.update((signText + "exception").getBytes("UTF-8"));

        boolean exceptionResult = signature2.verify(digitalsignature);

        System.out.println("exceptionVerifyResult:" + exceptionResult);

        System.out.println("=============测试国密证书数字签名=============");
    }

    public static void TestEncryptDecrypt() {
//        String estr = "GEWqTcEC07N2M36WSwUvNTbtHpAt3PiA4pA/kEEaSK7wZFz1pprMfBNMalOgMAXR7ZHD3nPLMeC9tGPo8XIS9aIviFe1pDORXLsFEChfsRf4nobb+/V+T1XFto2u9hGt2qFLVWRisa/4eX5l77HgXpxZRaEzbS8hgTSc439cG4xYYO4K";
//        String privaKeyStr = "MIGNAgEAMBMGByqGSM49AgEGCCqGSM49AwEEBHMwcQIBAQQeXdauHRsFnNYbcmOZP45CDbumd+2/7Q5v0150HJRwoAoGCCqGSM49AwEEoUADPgAECcodW0imLwYQc0o3lQWysEyi2NIvHZEwWQZXQerTGQC4FPZByMGubRfsVmO/qfhO3ifFgp6NS8hhFzty";
        try {

            String sourceStr = "这是加密测试数据";
            byte[] sourceByde = sourceStr.getBytes();

            KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
            g.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));
            KeyPair p = g.generateKeyPair();
            PrivateKey privateKey = p.getPrivate();
            PublicKey publicKey = p.getPublic();


            String base64Pubkey = Base64.toBase64String(publicKey.getEncoded());

            byte[] keyBytes = Base64.decode(base64Pubkey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            publicKey = keyFactory.generatePublic(keySpec);


            BCECPublicKey localECPublicKey = (BCECPublicKey) publicKey;
            ECParameterSpec localECParameterSpec = localECPublicKey.getParameters();
            ECDomainParameters localECDomainParameters = new ECDomainParameters(localECParameterSpec.getCurve(), localECParameterSpec.getG(), localECParameterSpec.getN());
            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(localECPublicKey.getQ(), localECDomainParameters);

            SM2Engine engine = new SM2Engine();
            ParametersWithRandom pwr = new ParametersWithRandom(publicKeyParameters, new SecureRandom());
            engine.init(true, pwr);
            byte[] encryptByte = engine.processBlock(sourceByde, 0, sourceByde.length);
            System.out.println("加密后的数据:" + Base64.toBase64String(encryptByte));

//            engine = new SM2Engine();
//            pwr = new ParametersWithRandom(publicKeyParameters, new SecureRandom());
//            engine.init(true, pwr);
            encryptByte = engine.processBlock(sourceByde, 0, sourceByde.length);
            System.out.println("加密后的数据:" + Base64.toBase64String(encryptByte));


//            engine = new SM2Engine();
//            pwr = new ParametersWithRandom(publicKeyParameters, new SecureRandom());
//            engine.init(true, pwr);
            encryptByte = engine.processBlock(sourceByde, 0, sourceByde.length);
            System.out.println("加密后的数据:" + Base64.toBase64String(encryptByte));


            String Base64pri = Base64.toBase64String(privateKey.getEncoded());//privatekey转成base64
            System.out.println(Base64pri);
            byte[] privateEn = Base64.decode(Base64pri);//privateKey.getEncoded();
            System.out.println(Base64.toBase64String(privateEn));

            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateEn);//BASE64转privatekey
            keyFactory = KeyFactory.getInstance("EC", "BC");
            privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

            System.out.println(Base64.toBase64String(privateKey.getEncoded()));

            engine = new SM2Engine();
            BCECPrivateKey sm2PriK = (BCECPrivateKey) privateKey;
            localECParameterSpec = sm2PriK.getParameters();
            localECDomainParameters = new ECDomainParameters(localECParameterSpec.getCurve(), localECParameterSpec.getG(), localECParameterSpec.getN());
            ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(sm2PriK.getD(), localECDomainParameters);
            engine.init(false, privateKeyParameters);

            byte[] decryptByte = engine.processBlock(encryptByte, 0, encryptByte.length);

            String reStr = new String(decryptByte);

            System.out.println(reStr);
        } catch (Exception ex) {

        }


    }

    public static void TestCipherEncryptDecrypt() {
//        String estr = "GEWqTcEC07N2M36WSwUvNTbtHpAt3PiA4pA/kEEaSK7wZFz1pprMfBNMalOgMAXR7ZHD3nPLMeC9tGPo8XIS9aIviFe1pDORXLsFEChfsRf4nobb+/V+T1XFto2u9hGt2qFLVWRisa/4eX5l77HgXpxZRaEzbS8hgTSc439cG4xYYO4K";
//        String privaKeyStr = "MIGNAgEAMBMGByqGSM49AgEGCCqGSM49AwEEBHMwcQIBAQQeXdauHRsFnNYbcmOZP45CDbumd+2/7Q5v0150HJRwoAoGCCqGSM49AwEEoUADPgAECcodW0imLwYQc0o3lQWysEyi2NIvHZEwWQZXQerTGQC4FPZByMGubRfsVmO/qfhO3ifFgp6NS8hhFzty";
        try {

            String sourceStr = "这是加密测试数据";
            byte[] sourceByde = sourceStr.getBytes();

            KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
            g.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));
            KeyPair p = g.generateKeyPair();
            PrivateKey privateKey = p.getPrivate();
            PublicKey publicKey = p.getPublic();


            String base64Pubkey = Base64.toBase64String(publicKey.getEncoded());

            byte[] keyBytes = Base64.decode(base64Pubkey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            publicKey = keyFactory.generatePublic(keySpec);


            BCECPublicKey localECPublicKey = (BCECPublicKey) publicKey;
            ECParameterSpec localECParameterSpec = localECPublicKey.getParameters();
            ECDomainParameters localECDomainParameters = new ECDomainParameters(localECParameterSpec.getCurve(), localECParameterSpec.getG(), localECParameterSpec.getN());
            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(localECPublicKey.getQ(), localECDomainParameters);


            // 对数据加密
            Cipher cipher = Cipher.getInstance("SM3", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] doFinal = cipher.doFinal(sourceByde);
            System.out.println("加密后的数据:" + Base64.toBase64String(doFinal));


            String Base64pri = Base64.toBase64String(privateKey.getEncoded());//privatekey转成base64
            System.out.println(Base64pri);
            byte[] privateEn = Base64.decode(Base64pri);//privateKey.getEncoded();
            System.out.println(Base64.toBase64String(privateEn));

            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateEn);//BASE64转privatekey
            keyFactory = KeyFactory.getInstance("EC", "BC");
            privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

            System.out.println(Base64.toBase64String(privateKey.getEncoded()));

            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] decryptByte = cipher.doFinal(doFinal);


            String reStr = new String(decryptByte);

            System.out.println(reStr);
        } catch (Exception ex) {
            System.out.println(ex.toString());
        }


    }

    public static void testSaveGMKeyStore() throws Exception {
        System.out.println("=============测试国密证书PKCS12 KeyStore存取=============");
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(readFile("custPrivateKey"));

        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509", "BC");

        Certificate certificate = certificateFactory.generateCertificate(new FileInputStream("custCert.cer"));

        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");

        keyStore.load(null, null);

        keyStore.setKeyEntry("test", privateKey, "32145698745632145698745632145698".toCharArray(), new Certificate[]{certificate});

        keyStore.store(new FileOutputStream("cust.pfx"), "32145698745632145698745632145698".toCharArray());

        KeyStore keyStore1 = KeyStore.getInstance("PKCS12", "BC");

        keyStore1.load(new FileInputStream("cust.pfx"), "32145698745632145698745632145698".toCharArray());

        Certificate certificate1 = keyStore1.getCertificate("test");

        PrivateKey privateKey1 = (PrivateKey) keyStore1.getKey("test", "32145698745632145698745632145698".toCharArray());

        System.out.println("公钥证书存取前后对比:" + Arrays.equals(certificate1.getEncoded(), certificate.getEncoded()));

        System.out.println("私钥存取前后对比:" + Arrays.equals(privateKey1.getEncoded(), privateKey1.getEncoded()));

        System.out.println("=============测试国密证书PKCS12 KeyStore存取=============");

    }


    public static void saveFile(String path, byte[] data) {
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(path);
            fileOutputStream.write(data);
            fileOutputStream.flush();
            fileOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    public static byte[] readFile(String path) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(path);
        byte[] bytes = new byte[fileInputStream.available()];
        fileInputStream.read(bytes);
        return bytes;
    }


    public static byte[] getPriKeyByteFromP8(byte[] p8byte) throws Exception {

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(p8byte);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        ASN1InputStream asn1InputStream = new ASN1InputStream(privateKey.getEncoded());

        ASN1Sequence p8 = (ASN1Sequence) asn1InputStream.readObject();

        ASN1InputStream asn1InputStream1 = new ASN1InputStream(((DEROctetString) p8.getObjectAt(2)).getOctets());

        ASN1Sequence gmPrivateKey = (ASN1Sequence) asn1InputStream1.readObject();

        byte[] gmPriKeyBytes = ((DEROctetString) gmPrivateKey.getObjectAt(1)).getOctets();

        return gmPriKeyBytes;
    }

    public static void tetsGudongall() {
        String enStr1 = "tfC7kDO6V7V/KoLEtd+Q7ekuSbqFu+oBy6z9sobWNOKxM1cL9F/ltPoUv+H0p01KGb5OkVy7NuxOxtzYcfeyGe7eNpTmC76PmzyXZJ02GhNVYSdZcTudL5E3XsO11RazLwCXGdN2zLF61hnc6hWJvmSyeEGLRjM0NdV+CWyX47W6kAPi";
        String enStr2 = "MLfBJ/4guOXYi30fmJkhUesngJB4SJ0uM1Z1m/y/Hzlp9/xNns4Fn7JIhYxCdo0BZjHsWm2v1qhFgV7NFA9vFZBQ4ke/27P0r2QKLs3xGdwWkUnb/GjSQjAdIy86fzGxni09R3DK/vbApxw0nOhz2BqdEXsHT0uNaAqF2k5KnlwiiGeq";
        String privateStr = "MIGNAgEAMBMGByqGSM49AgEGCCqGSM49AwEEBHMwcQIBAQQeXdauHRsFnNYbcmOZP45CDbumd+2/7Q5v0150HJRwoAoGCCqGSM49AwEEoUADPgAECcodW0imLwYQc0o3lQWysEyi2NIvHZEwWQZXQerTGQC4FPZByMGubRfsVmO/qfhO3ifFgp6NS8hhFzty";
        try {
            byte[] privateEn = Base64.decode(privateStr);//privateKey.getEncoded();
            System.out.println(Base64.toBase64String(privateEn));

            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateEn);//BASE64转privatekey
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

            SM2Engine engine = new SM2Engine();
            BCECPrivateKey sm2PriK = (BCECPrivateKey) privateKey;
            ECParameterSpec localECParameterSpec = sm2PriK.getParameters();
            ECDomainParameters localECDomainParameters = new ECDomainParameters(localECParameterSpec.getCurve(), localECParameterSpec.getG(), localECParameterSpec.getN());
            ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(sm2PriK.getD(), localECDomainParameters);
            engine.init(false, privateKeyParameters);
            //66字节开始的32字节移动到最后，看看。前面65字节不动，中间32字节向后移动到末尾，后面的向前移动
            byte[] sourceByte = Base64.decode(enStr1);
            byte[] encryptByte = new byte[sourceByte.length];
            byte[] tempByte = new byte[32];
            for (int i = 0; i < sourceByte.length; i++) {
                if (i < 66) {
                    encryptByte[i] = sourceByte[i];
                } else if (i < 98) {
                    tempByte[i - 66] = sourceByte[i];

                } else {
                    encryptByte[i - 32] = sourceByte[i];
                }

            }
            for (int i = 0; i < tempByte.length; i++) {
                encryptByte[sourceByte.length-32+i]=tempByte[i];
            }

            byte[] decryptByte = engine.processBlock(sourceByte, 0, sourceByte.length);

            String reStr = new String(decryptByte);

            System.out.println(reStr);
        } catch (Exception ex) {
            System.out.println(ex.toString());
        }
    }


}
