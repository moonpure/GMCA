import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public class RSACA {
    public static  void createReq() throws Exception
    {
        KeyPairGenerator keyPairGenerator= KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.genKeyPair();

//            有效的DN(Distinct Name)标识：
//            c          country code (一般是c=cn)
//            o          organization(组织)
//                    ou        organizational unit name(组织单位名)
//            cn        common name (普通名)
//            e          email (邮件地址)
//                    l           locality name (地址)
//                    st         state, or province name (国家或省份名)
//                    dc        domain Component (领域)
//                    uid      user id (用户标识符)
//                    t          title (标题)
//            sn        device serial number name
//        数字证书中主题(Subject)中字段的含义
//        一般的数字证书产品的主题通常含有如下字段：
//        公用名称 (Common Name) 简称：CN 字段，对于 SSL 证书，一般为网站域名或IP地址；而对于代码签名证书则为申请单位名称；而对于客户端证书则为证书申请者的姓名；
//        单位名称 (Organization Name) ：简称：O 字段，对于 SSL 证书，一般为网站域名；而对于代码签名证书则为申请单位名称；而对于客户端单位证书则为证书申请者所在单位名称；
//        证书申请单位所在地：
//        所在城市 (Locality) 简称：L 字段
//        所在省份 (State/Provice) 简称：S 字段
//        所在国家 (Country) 简称：C 字段，只能是国家字母缩写，如中国：CN
//        其他一些字段：
//        电子邮件 (Email) 简称：E 字段
//        多个姓名字段 简称：G 字段
//        介绍：Description 字段
//        电话号码：Phone 字段，格式要求 + 国家区号 城市区号 电话号码，如： +86 732 88888888
//        地址：STREET  字段
//        邮政编码：PostalCode 字段
//        显示其他内容 简称：OU 字段
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.C, "CN");
        nameBuilder.addRDN(BCStyle.O, "412941523");
        nameBuilder.addRDN(BCStyle.OU, "412941523");
        nameBuilder.addRDN(BCStyle.CN, "412941523@qq.com");
        nameBuilder.addRDN(BCStyle.E, "412941523@qq.com");
        nameBuilder.addRDN(BCStyle.L, "beijin");
        nameBuilder.addRDN(BCStyle.ST, "beijin");
        nameBuilder.addRDN(BCStyle.DC, "Study");
        nameBuilder.addRDN(BCStyle.UID, "huangqijunCAcert");
        nameBuilder.addRDN(BCStyle.T, "huangqijun person cert");
        nameBuilder.addRDN(BCStyle.NAME, "412941523@qq.com");
        nameBuilder.addRDN(BCStyle.SN, "412941523@qq.com");
      //  nameBuilder.addRDN(BCStyle.SN, "huanqijunCAcertsn");
        X500Name subDN = nameBuilder.build();
        //JcaContentSignerBuilder jcaBuilder = new JcaContentSignerBuilder("sha1withrsa");
        //jcaBuilder.setProvider("BC"); 这里可以添加提供者
       // ContentSigner contentSigner = jcaBuilder.build(keyPair.getPrivate());
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA512WITHRSA").setProvider("BC").build(keyPair.getPrivate());

        PKCS10CertificationRequestBuilder pkcs10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(subDN,keyPair.getPublic());
        PKCS10CertificationRequest pkcs10CertificationRequest = pkcs10CertificationRequestBuilder.build(contentSigner);
        System.out.println("证书请求:"+ Base64.toBase64String(pkcs10CertificationRequest.getEncoded()));



//        ByteArrayOutputStream bos = new ByteArrayOutputStream();
//        JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(new PrintWriter(bos));
//        jcaPEMWriter.writeObject(pkcs10CertificationRequest);
//        jcaPEMWriter.flush();
//        String stai=bos.toString();
//        System.out.println("证书请求bosString:"+stai);

//        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(subDN, SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
//        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder("SHA512WITHRSA");
//        contentSigner = jcaContentSignerBuilder.build(keyPair.getPrivate());
//        builder.build(contentSigner);

        String csrString = csrToString(pkcs10CertificationRequest);
        System.out.println("证书请求toString:"+csrString);

//        GMCA.saveFile("CAcertPrivatekey",Base64.encode( keyPair.getPrivate().getEncoded()));
//        GMCA.saveFile("CAcertPublickey", Base64.encode( keyPair.getPublic().getEncoded()));
        GMCA.saveFile("CAcertPrivatekey", keyPair.getPrivate());
       GMCA.saveFile("CAcertPublickey", keyPair.getPublic());
        GMCA.saveFile("CAcertReq", Base64.encode(pkcs10CertificationRequest.getEncoded()));
        GMCA.saveFile("CAcertReqObj",pkcs10CertificationRequest);
        //验证证书请求
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().setProvider("BC").build(pkcs10CertificationRequest.getSubjectPublicKeyInfo());
        boolean isValid = pkcs10CertificationRequest.isSignatureValid(verifier);
        System.out.println(isValid);
    }
    private static String csrToString(PKCS10CertificationRequest csr) throws IOException {
        StringWriter w = new StringWriter();
        JcaPEMWriter p = new JcaPEMWriter(w);
        p.writeObject(csr);
        p.close();
        return w.toString();
    }
}
