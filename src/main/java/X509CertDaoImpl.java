import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


public class X509CertDaoImpl {
    public static final String Default_keyType = "PKCS12";
    public static final String Default_KeyPairGenerator = "RSA";
    public static final String Default_Signature = "SHA1withRSA";
    public static final String cert_type = "X509";
    public static final Integer Default_KeySize = 2048;

    static {
        // 系统添加BC加密算法 以后系统中调用的算法都是BC的算法
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * @param issuer       发布者  C=CN,ST=BJ,L=BJ,O=组织,OU=单位,CN=CCERT
     * @param notBefore    使用日期
     * @param notAfter     到期
     * @param certDestPath 生成证书地址
     * @param serial       证书序列号
     * @param alias        证书别名
     * @throws Exception
     */
    public void createCert(String issuer, Date notBefore, Date notAfter, String certDestPath,
                           BigInteger serial, String keyPassword, String alias) throws Exception {
        //产生公私钥对
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(Default_KeyPairGenerator);
        kpg.initialize(Default_KeySize);
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        // 组装证书
        X500Name issueDn = new X500Name(issuer);
        X500Name subjectDn = new X500Name(issuer);
        //组装公钥信息
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo
                .getInstance(new ASN1InputStream(publicKey.getEncoded())
                        .readObject());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                issueDn, serial, notBefore, notAfter, subjectDn,
                subjectPublicKeyInfo);
        //证书的签名数据
        ContentSigner sigGen = new JcaContentSignerBuilder(Default_Signature).build(privateKey);
        X509CertificateHolder holder = builder.build(sigGen);
        byte[] certBuf = holder.getEncoded();
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance(cert_type).generateCertificate(new ByteArrayInputStream(certBuf));
        // 创建KeyStore,存储证书
        KeyStore store = KeyStore.getInstance(Default_keyType);
        store.load(null, null);
        store.setKeyEntry(alias, keyPair.getPrivate(),
                keyPassword.toCharArray(), new Certificate[]{certificate});
        FileOutputStream fout = new FileOutputStream(certDestPath);
        store.store(fout, keyPassword.toCharArray());
        fout.close();
    }


    /**
     * 输出证书信息
     *
     * @param certPath    证书地址
     * @param keyPassword 证书密码
     */

    public void printCert(String certPath, String keyPassword) throws Exception {
        char[] charArray = keyPassword.toCharArray();
        KeyStore ks = KeyStore.getInstance(Default_keyType);
        FileInputStream fis = new FileInputStream(certPath);
        ks.load(fis, charArray);
        fis.close();
        System.out.println("keystore type=" + ks.getType());
        Enumeration enumas = ks.aliases();
        String keyAlias = null;
        if (enumas.hasMoreElements()) {
            keyAlias = (String) enumas.nextElement();
            System.out.println("alias=[" + keyAlias + "]");
        }
        System.out.println("is key entry=" + ks.isKeyEntry(keyAlias));
        PrivateKey prikey = (PrivateKey) ks.getKey(keyAlias, charArray);
        Certificate cert = ks.getCertificate(keyAlias);
        PublicKey pubkey = cert.getPublicKey();
        System.out.println("cert class = " + cert.getClass().getName());
        System.out.println("cert = " + cert);
        System.out.println("public key = " + pubkey);
        System.out.println("private key = " + prikey);
    }

    /**
     * 返回公钥
     *
     * @param certPath    证书路径
     * @param keyPassword 证书密码
     * @return
     * @throws Exception
     */

    public PublicKey getPublicKey(String certPath, String keyPassword) throws Exception {
        char[] charArray = keyPassword.toCharArray();
        KeyStore ks = KeyStore.getInstance(Default_keyType);
        FileInputStream fis = new FileInputStream(certPath);
        ks.load(fis, charArray);
        fis.close();
        Enumeration enumas = ks.aliases();
        String keyAlias = null;
        if (enumas.hasMoreElements()) {
            keyAlias = (String) enumas.nextElement();
            Certificate certificate = ks.getCertificate(keyAlias);

            return ks.getCertificate(keyAlias).getPublicKey();
        }
        return null;
    }

    /**
     * 返回私钥
     *
     * @param certPath
     * @param keyPassword
     * @return
     * @throws Exception
     */
    public PrivateKey getPrivateKey(String certPath, String keyPassword) throws Exception {
        char[] charArray = keyPassword.toCharArray();
        KeyStore ks = KeyStore.getInstance(Default_keyType);
        FileInputStream fis = new FileInputStream(certPath);
        ks.load(fis, charArray);
        fis.close();
        Enumeration enumas = ks.aliases();
        String keyAlias = null;
        if (enumas.hasMoreElements()) {
            keyAlias = (String) enumas.nextElement();
            Certificate certificate = ks.getCertificate(keyAlias);

            return (PrivateKey) ks.getKey(keyAlias, charArray);
        }
        return null;
    }

    /**
     * @param endTime  延期时间
     * @param certPath 证书地址
     * @param password 密码
     * @throws Exception 目前未实现，
     */
    public void certDelayTo(Date endTime, String certPath, String password) throws Exception {

    }

    /**
     * 修改密码
     *
     * @param certPath 证书地址 密码
     * @param oldPwd   原始密码
     * @param newPwd   新密码
     * @throws Exception
     */
    public void changePassword(String certPath, String oldPwd, String newPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance(Default_keyType);
        FileInputStream fis = new FileInputStream(certPath);
        ks.load(fis, oldPwd.toCharArray());
        fis.close();
        FileOutputStream output = new FileOutputStream(certPath);
        ks.store(output, newPwd.toCharArray());
        output.close();
    }

    /**
     * 删除证书
     *
     * @param certPath 证书地址
     * @param password 密码
     * @param alias    别名
     * @param entry    条目
     * @throws Exception
     */

    public void deleteAlias(String certPath, String password, String alias, String entry) throws Exception {
        char[] charArray = password.toCharArray();
        KeyStore ks = KeyStore.getInstance(Default_keyType);
        FileInputStream fis = new FileInputStream(certPath);
        ks.load(fis, charArray);
        fis.close();
        if (ks.containsAlias(alias)) {
            ks.deleteEntry(entry);
            FileOutputStream output = new FileOutputStream(certPath);
            ks.store(output, password.toCharArray());
            output.close();
        } else {
            throw new Exception("该证书未包含别名--->" + alias);
        }
    }

    public static void main(String[] args) throws Exception {
        X509CertDaoImpl impl = new X509CertDaoImpl();
        String issuer = "C=CN,ST=BJ,L=BJ,O=testserver,OU=testserver,CN=testserver";
        String certDestPath = "e://test.p12";
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        String keyPassword = "123";
        String alias = "test";
        //impl.createCert(issuer, new Date(), new Date("2017/09/27"), certDestPath, serial, keyPassword, alias);
        //impl.changePassword(certDestPath, "123", "123");
        //impl.createCert(issuer, new Date(), new Date("2017/09/27"), certDestPath, serial, keyPassword, alias);
        //未实现
        impl.certDelayTo(new Date("2017/09/28"), certDestPath, keyPassword);
        //impl.printCert(certDestPath, keyPassword);
    }


}
