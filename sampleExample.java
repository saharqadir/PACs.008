package bulkIbanRaastTesting;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.TimeZone;
import java.util.UUID;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URI;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.Data;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.KeySelector.Purpose;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.nccpl.gen.dao.NCSSAppDatabaseManager;


public class sampleExample {

	  Document doc=null;
	//public Document sign(
	  public String sign(
			org.w3c.dom.Document doc,
			java.security.cert.X509Certificate signerCertificate,
			java.security.PrivateKey privateKey,
			boolean debugLog
			) 
			throws Exception 
			{

			System.out.println("In sign method");
			final String xadesNS = "http://uri.etsi.org/01903/v1.3.2#";
			final String signedpropsIdSuffix = "-signedprops";


			XMLSignatureFactory fac = null;
			try {
				System.out.println("In try");
			   fac = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
			} catch (NoSuchProviderException ex) {
				System.out.println("In catch");
			   fac = XMLSignatureFactory.getInstance("DOM");
			}
			System.out.println("after try ");			
			// 1. Prepare KeyInfo
			System.out.println("In Prepare KeyInfo");
			KeyInfoFactory kif = fac.getKeyInfoFactory();
			X509IssuerSerial x509is = kif.newX509IssuerSerial(
					signerCertificate.getIssuerX500Principal().toString(),
					signerCertificate.getSerialNumber());
			X509Data x509data = kif.newX509Data(Collections.singletonList(x509is));
			final String keyInfoId = "_" + UUID.randomUUID().toString();
			KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509data), keyInfoId);

			// 2. Prepare references
			System.out.println("In Prepare references");
			List<Reference> refs = new ArrayList<Reference>();

			/*Reference ref1 = fac.newReference("#" + keyInfoId,fac.newDigestMethod(DigestMethod.SHA256, null), Collections.singletonList(fac.newCanonicalizationMethod( CanonicalizationMethod.EXCLUSIVE, (XMLStructure) null)), null, null);
			refs.add(ref1);

			final String signedpropsId = "_" + UUID.randomUUID().toString() + signedpropsIdSuffix;

			//Reference ref2 = fac.newReference("#" + signedpropsId, fac.newDigestMethod(DigestMethod.SHA256, null), Collections.singletonList(fac.newCanonicalizationMethod( CanonicalizationMethod.EXCLUSIVE, (XMLStructure) null)), "http://uri.etsi.org/01903/v1.3.2#SignedProperties", null);
			Reference ref2 = fac.newReference("#" + signedpropsId, fac.newDigestMethod(DigestMethod.SHA256, null), Collections.singletonList(fac.newCanonicalizationMethod( CanonicalizationMethod.EXCLUSIVE, (XMLStructure) null)),null, null);
			refs.add(ref2);

			Reference ref3 = fac.newReference(null,fac.newDigestMethod(DigestMethod.SHA256, null), Collections.singletonList(fac.newCanonicalizationMethod( CanonicalizationMethod.EXCLUSIVE, (XMLStructure) null)),null, null);
			refs.add(ref3);
			*/
			
			Reference ref1 = fac.newReference(null,fac.newDigestMethod(DigestMethod.SHA256, null), Collections.singletonList(fac.newCanonicalizationMethod( CanonicalizationMethod.EXCLUSIVE, (XMLStructure) null)),null, null);
			refs.add(ref1);
			
			Reference ref2 = fac.newReference("#" + keyInfoId,fac.newDigestMethod(DigestMethod.SHA256, null), Collections.singletonList(fac.newCanonicalizationMethod( CanonicalizationMethod.EXCLUSIVE, (XMLStructure) null)), null, null);
			refs.add(ref2);

			final String signedpropsId = "_" + UUID.randomUUID().toString() + signedpropsIdSuffix;

			Reference ref3 = fac.newReference("#" + signedpropsId, fac.newDigestMethod(DigestMethod.SHA256, null), Collections.singletonList(fac.newCanonicalizationMethod( CanonicalizationMethod.EXCLUSIVE, (XMLStructure) null)),null, null);
			refs.add(ref3);

			

			SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (XMLStructure) null), fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), refs);

			// 3. Create element AppHdr/Sgntr that will contain the <ds:Signature>
			System.out.println("In Create element AppHdr/Sgntr that will contain the <ds:Signature>");
			Node appHdr = null;
			NodeList sgntrList = doc.getElementsByTagName("AppHdr");
			if (sgntrList.getLength() != 0)
				appHdr = sgntrList.item(0);

			if (appHdr == null)
				throw new Exception("mandatory element AppHdr is missing in the document to be signed");


			Node sgntr = appHdr.appendChild(doc.createElementNS(appHdr.getNamespaceURI(), "Sgntr"));

			DOMSignContext dsc = new DOMSignContext(privateKey, sgntr);
			if (debugLog) {
			   dsc.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
			}
			dsc.putNamespacePrefix(XMLSignature.XMLNS, "ds");

			// 4. Set up <ds:Object> with <QualifiyingProperties> inside that includes SigningTime
			System.out.println("In  Set up <ds:Object> with <QualifiyingProperties> inside that includes SigningTime");
			Element QPElement = doc.createElementNS(xadesNS, "xades:QualifyingProperties");
			QPElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xades", xadesNS);

			Element SPElement = doc.createElementNS(xadesNS, "xades:SignedProperties");
			SPElement.setAttributeNS(null, "Id", signedpropsId);
			dsc.setIdAttributeNS(SPElement, null, "Id");
			SPElement.setIdAttributeNS(null, "Id", true);
			QPElement.appendChild(SPElement);

			Element SSPElement = doc.createElementNS(xadesNS, "xades:SignedSignatureProperties");
			SPElement.appendChild(SSPElement);

			final DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
			String signingTime = df.format(new Date());

			Element STElement = doc.createElementNS(xadesNS, "xades:SigningTime");
			STElement.appendChild(doc.createTextNode(signingTime));
			SSPElement.appendChild(STElement);

			DOMStructure qualifPropStruct = new DOMStructure(QPElement);

			List<DOMStructure> xmlObj = new ArrayList<DOMStructure>();
			xmlObj.add(qualifPropStruct);
			XMLObject object = fac.newXMLObject(xmlObj, null, null, null);

			List<XMLObject> objects = Collections.singletonList(object);


			// 5. Set up custom URIDereferencer to process Reference without URI.
			// This Reference points to element <Document> of MX message 
			System.out.println("In  Set up custom URIDereferencer to process Reference without URI.");
			final NodeList docNodes = doc.getElementsByTagName("Document");
			final Node docNode = docNodes.item(0);

			ByteArrayOutputStream refOutputStream = new ByteArrayOutputStream();
			Transformer xform = TransformerFactory.newInstance().newTransformer();
			xform.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			xform.transform(new DOMSource(docNode), new StreamResult(refOutputStream));
			InputStream refInputStream = new ByteArrayInputStream(refOutputStream.toByteArray()); 
			dsc.setURIDereferencer(new NoUriDereferencer(refInputStream));

			// 6. sign it!
			System.out.println("In sign it!");
			XMLSignature signature = fac.newXMLSignature(si, ki, objects, null, null);
			signature.sign(dsc);

			// 7. for debug purposes for each reference
//			    write the digest and the transformed data 
//			    to the console (replace with your preferred logging such as log4j)
			System.out.println("for debug purposes for each reference");
			if (debugLog) {
			      int i = 0;
			      for (Reference ref: refs) {
			         StringBuilder sb = new StringBuilder();
			         String digValStr = digestToString(ref.getDigestValue());
			            InputStream is = ref.getDigestInputStream();
			            InputStreamReader isr = new InputStreamReader(is);
			            BufferedReader br = new BufferedReader(isr);
			            String line;
			            while ((line = br.readLine()) != null) {
			                sb.append(line).append("\n");
			            }
			            is.close();
			            i++;
			            System.out.println( ("ref #" + i + " URI: [" + ref.getURI() +"], digest: " + digValStr + ", transformed data: [" + sb.toString() + "]"));
			      }
			}
			//return doc;
			TransformerFactory TRANSFORMER_FACTORY = TransformerFactory.newInstance();
			  StringWriter strWriter = new StringWriter();
		        TRANSFORMER_FACTORY.newTransformer().transform(new DOMSource(doc), new StreamResult(strWriter));
		        System.out.println("strWriter "+strWriter);
		        return strWriter.toString();

			}

	private String digestToString(byte[] digestValue) {
		// TODO Auto-generated method stub
		return null;
	}

	  public static X509Certificate getCertificate() {
	    	String crtUrl =  "/ncsswblj/java6_64/bin/certnew.cer";
	        InputStream is = null;
	        try {
	            is = new FileInputStream(new File(crtUrl));
	            CertificateFactory cf = CertificateFactory.getInstance("X.509");
	            X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
	            return cert;
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	        return null;
	    }
	  
	  public static PrivateKey getPrivateKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
	      
	    	File is = new File("/ncsswblj/java6_64/bin/raastcertfinal.jks");
			 PrivateKey  priKey = loadKeyStore(is,"storepassraastfinal", "JKS");
			 String keypem  = "-----BEGIN PRIVATE KEY-----\n" + DatatypeConverter.printBase64Binary(priKey.getEncoded()) + "\n-----END PRIVATE KEY-----\n";
			 return priKey;
	    }
	  
	  public static PrivateKey loadKeyStore(final File keystoreFile,
			    final String password, final String keyStoreType)
			    throws KeyStoreException, IOException, NoSuchAlgorithmException,
			    CertificateException, UnrecoverableKeyException {
			  if (null == keystoreFile) {
			    throw new IllegalArgumentException("Keystore url may not be null");
			  }
			  PrivateKey key = null;
			  final URI keystoreUri = keystoreFile.toURI();
			  final URL keystoreUrl = keystoreUri.toURL();
			  final KeyStore keystore = KeyStore.getInstance(keyStoreType);
			  InputStream is = null;
			  try {
			    is = keystoreUrl.openStream();
			    keystore.load(is, null == password ? null : password.toCharArray());
			    key = (PrivateKey)keystore.getKey("aliasraastfinal", "keypassraastfinal".toCharArray());
			    System.out.println("key store Loaded ");
		        
		        java.security.cert.Certificate cert = keystore.getCertificate("aliasraastfinal"); 
			    
		        
			  } finally {
			    if (null != is) {
			      is.close();
			    }
			  }
			  return key;
			}
	  
	  
	  public Document getW3cDoc() {
		  	System.out.println("In getw3Doc method ::: ");
	        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	        DocumentBuilder builder = null;
	        //Document doc=null;
	        try {
	        	
	        	String bizMsgId=getRAAST_PAYMENT_BIZ_MSG_ID();
	        	String msgId=getRAAST_PAYMENT_MSG_ID();
	        	String instrID =  getRAAST_PAYMENT_INSTRUCTION_ID();
	        	String endToEndId =  getRAAST_PAYMENT_ENDTOEND_ID();
	        	
	        	System.out.println("In try block of getw3Doc method :::::: ");
	            builder = factory.newDocumentBuilder();
	            System.out.println("after builder::::::: ");
	            
	            //char quotes = '"';
	            String quotes = "'";
	            char slash = '/';
	            //doc = builder.parse(new InputSource(new StringReader("<DataPDU xmlns="+quotes+"urn:cma:stp:xsd:stp.1.0"+quotes+">" + 
	            doc = builder.parse(new InputSource(new StringReader("<DataPDU xmlns='urn:cma:stp:xsd:stp.1.0'>" +
	            		"<Body>" + 
	            		//"<AppHdr xmlns="+quotes+"urn:iso:std:iso:20022:tech:xsd:head.001.001.01"+quotes+">" + 
	            		/*"<AppHdr xmlns='urn:iso:std:iso:20022:tech:xsd:head.001.001.01'>" +
	            		"<Fr>" + 
	            		"<FIId>" + 
	            		"<FinInstnId>" + 
	            		"<ClrSysMmbId>" + 
	            		"<MmbId>NCCPPKKA</MmbId>" + 
	            		"</ClrSysMmbId>" + 
	            		"</FinInstnId>" + 
	            		"</FIId>" + 
	            		"</Fr>" + 
	            		"<To>" + 
	            		"<FIId>" + 
	            		"<FinInstnId>" + 
	            		"<ClrSysMmbId>" + 
	            		"<MmbId>MEZNPKKA</MmbId>" + 
	            		"</ClrSysMmbId>" + 
	            		"</FinInstnId>" + 
	            		"</FIId>" + 
	            		"</To>" + 
	            		//"<BizMsgIdr>20240524NCC005</BizMsgIdr>" +
	            		"<BizMsgIdr>"+bizMsgId+"</BizMsgIdr>"+ 
	            		"<MsgDefIdr>pacs.008.001.08</MsgDefIdr>" + 
	            		"<BizSvc>ACH</BizSvc>" + 
	            		//"<CreDt>2024-05-24T17:05:45.087Z</CreDt>" + 
	            		"<CreDt>"+getDatetime()+"</CreDt>" +
	            		"</AppHdr>" +*/ 
	            		//"<Document xmlns="+quotes+"urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08"+quotes+">" + 
	            		"<Document xmlns='urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08'>" +
	            		"<FIToFICstmrCdtTrf>" + 
	            		"<GrpHdr>" + 
	            		//"<MsgId>NCC20240000MEZN1111NCCPPKK05<"+slash+"MsgId>" +
	            		"<MsgId>"+msgId+"<"+slash+"MsgId>" +
	            		//"<CreDtTm>2024-05-24T17:05:45.087Z</CreDtTm>" + 
	            		"<CreDtTm>"+getDatetime()+"</CreDtTm>" +
	            		"<BtchBookg>true</BtchBookg>" + 
	            		"<NbOfTxs>1</NbOfTxs>" + 
	            		//"<TtlIntrBkSttlmAmt Ccy="+quotes+"PKR"+quotes+">200</TtlIntrBkSttlmAmt>" + 
	            		"<TtlIntrBkSttlmAmt Ccy='PKR'>200</TtlIntrBkSttlmAmt>" +
	            		"<IntrBkSttlmDt>"+getOnlyDate()+"</IntrBkSttlmDt>" + 
	            		"<SttlmInf>" + 
	            		"<SttlmMtd>CLRG</SttlmMtd>" + 
	            		"</SttlmInf>" + 
	            		"</GrpHdr>" + 
	            		"<CdtTrfTxInf>" + 
	            		"<PmtId>" + 
	            		//"<InstrId>NCC20240000000011111NCC00005</InstrId>" +
	            		//"<EndToEndId>NCC2024000000001111NCCPPKK05</EndToEndId>" +
	            		//"<TxId>NCC20240000000011111NCC00005</TxId>" +
	            		"<InstrId>"+instrID+"</InstrId>" +
	            		"<EndToEndId>"+endToEndId+"</EndToEndId>" +
	            		"<TxId>"+instrID+"</TxId>" +
	            		"</PmtId>" + 
	            		"<PmtTpInf>" + 
	            		"<ClrChanl>RTNS</ClrChanl>" + 
	            		"<SvcLvl>" + 
	            		"<Prtry>0100</Prtry>" + 
	            		"</SvcLvl>" + 
	            		"<LclInstrm>" + 
	            		"<Prtry>CSDC</Prtry>" + 
	            		"</LclInstrm>" + 
	            		"<CtgyPurp>" + 
	            		"<Prtry>001</Prtry>" + 
	            		"</CtgyPurp>" + 
	            		"</PmtTpInf>" + 
	            		"<IntrBkSttlmAmt Ccy='PKR'>200.0</IntrBkSttlmAmt>" + 
	            		"<IntrBkSttlmDt>2024-05-24</IntrBkSttlmDt>" + 
	            		"<ChrgBr>SLEV</ChrgBr>" + 
	            		"<InstgAgt>" + 
	            		"<FinInstnId>" + 
	            		"<ClrSysMmbId>" + 
	            		"<MmbId>NCCPPKKA</MmbId>" + 
	            		"</ClrSysMmbId>" + 
	            		"</FinInstnId>" + 
	            		"</InstgAgt>" + 
	            		"<InstdAgt>" + 
	            		"<FinInstnId>" + 
	            		"<ClrSysMmbId>" + 
	            		"<MmbId>MEZNPKKA</MmbId>" + 
	            		"</ClrSysMmbId>" + 
	            		"</FinInstnId>" + 
	            		"</InstdAgt>" + 
	            		"<Dbtr>" + 
	            		"<Nm>X</Nm>" + 
	            		"</Dbtr>" + 
	            		"<DbtrAcct>" + 
	            		"<Id>" + 
	            		"<Othr>" + 
	            		"<Id>123456789</Id>" + 
	            		//"<IBAN>PK49MEZN0009810104546952</IBAN>" +
	            		"</Othr>" + 
	            		"</Id>" + 
	            		"</DbtrAcct>" + 
	            		"<DbtrAgt>" + 
	            		"<FinInstnId>" + 
	            		"<ClrSysMmbId>" + 
	            		"<MmbId>NCCPPKKA</MmbId>" + 
	            		"</ClrSysMmbId>" + 
	            		"</FinInstnId>" + 
	            		"</DbtrAgt>" + 
	            		"<CdtrAgt>" + 
	            		"<FinInstnId>" + 
	            		"<ClrSysMmbId>" + 
	            		"<MmbId>MEZNPKKA</MmbId>" + 
	            		"</ClrSysMmbId>" + 
	            		"</FinInstnId>" + 
	            		"</CdtrAgt>" + 
	            		"<Cdtr>" + 
	            		"<Nm> MEEZAN Bank Ltd.</Nm>" + 
	            		"<Id>" + 
	            		"<PrvtId>" + 
	            		"<Othr>" + 
	            		"<Id>4550115683514</Id>" + 
	            		"<SchmeNm>" + 
	            		"<Prtry>CNIC</Prtry>" + 
	            		"</SchmeNm>" + 
	            		"</Othr>" + 
	            		"</PrvtId>" + 
	            		"</Id>" + 
	            		"</Cdtr>" + 
	            		"<CdtrAcct>" + 
	            		"<Id>" + 
	            		"<Othr>" + 
	            		"<Id>PK39MEZN0012460104546951</Id>" + 
	            		//"<IBAN>PK39MEZN0012460104546951</IBAN>" +
	            		"</Othr>" + 
	            		"</Id>" + 
	            		"</CdtrAcct>" + 
	            		"<InstrForCdtrAgt>" + 
	            		"<InstrInf>Pacs.008 message</InstrInf>" + 
	            		"</InstrForCdtrAgt>" + 
	            		"<Purp>" + 
	            		"<Prtry>033</Prtry>" + 
	            		"</Purp>" +
	            		/*"<InstrForNxtAgt>" + 
	            		"<InstrInf>/BNF/Beneficiary info</InstrInf>" + 
	            		"</InstrForNxtAgt>" + 
	            		"<InstrForNxtAgt>" + 
	            		"<InstrInf>/SMPL/Sample data</InstrInf>" + 
	            		"</InstrForNxtAgt>"+*/
	            		"<RmtInf>" + 
	            		"<Ustrd>Meezan Bank Ltd.</Ustrd>" + 
	            		"</RmtInf>" + 
	            		"</CdtTrfTxInf>" + 
	            		"</FIToFICstmrCdtTrf>" + 
	            		"</Document>" + 
	            		"<AppHdr xmlns="+quotes+"urn:iso:std:iso:20022:tech:xsd:head.001.001.01"+quotes+">" + 
	            		"<Fr>" + 
	            		"<FIId>" + 
	            		"<FinInstnId>" + 
	            		"<ClrSysMmbId>" + 
	            		"<MmbId>NCCPPKKA</MmbId>" + 
	            		"</ClrSysMmbId>" + 
	            		"</FinInstnId>" + 
	            		"</FIId>" + 
	            		"</Fr>" + 
	            		"<To>" + 
	            		"<FIId>" + 
	            		"<FinInstnId>" + 
	            		"<ClrSysMmbId>" + 
	            		"<MmbId>MEZNPKKA</MmbId>" + 
	            		"</ClrSysMmbId>" + 
	            		"</FinInstnId>" + 
	            		"</FIId>" + 
	            		"</To>" + 
	            		"<BizMsgIdr>20240125204930</BizMsgIdr>" + 
	            		"<MsgDefIdr>pacs.008.001.08</MsgDefIdr>" + 
	            		"<BizSvc>ACH</BizSvc>" + 
	            		"<CreDt>2024-05-24T15:31:30.087Z</CreDt>" + 
	            		"</AppHdr>" + 
	            		"</Body>" + 
	            		"</DataPDU>")));
	           
	           
	             System.out.println("in method of doc::::: "+doc);
	              return doc;
	        } catch (ParserConfigurationException e) {
	        	System.out.println("in Parser Configuration Exception "+e.getMessage());
	            e.printStackTrace();
	        } catch (SAXException e) {
	        	System.out.println("in SAXException "+e.getMessage());
	            e.printStackTrace();
	        } catch (IOException e) {
	        	System.out.println("in IOException "+e.getMessage());
	            e.printStackTrace();
	        }
	
	        return doc;
	    }
	  
	  
	  public Document getW3cDocPaySys() {
		  	System.out.println("In getW3cDocPaySys method ::: ");
	        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	        DocumentBuilder builder = null;
	        //Document doc=null;
	        try {
	        	System.out.println("In try block of getw3Doc method :::::: ");
	            builder = factory.newDocumentBuilder();
	            System.out.println("after builder::::::: ");
	            
	            char quotes = '"';
	            char slash = '/';
	            doc = builder.parse(new InputSource(new StringReader("<DataPDU xmlns="+quotes+"urn:cma:stp:xsd:stp.1.0"+quotes+">" + 
	            		"<Body>" + 
	            		"<AppHdr xmlns=\"urn:iso:std:iso:20022:tech:xsd:head.001.001.01\">" + 
	            		"<Fr>" + 
	            		"<FIId>" + 
	            		"<FinInstnId>" + 
	            		"<ClrSysMmbId>" + 
	            		"<MmbId>NCCPPKKA</MmbId>" + 
	            		"</ClrSysMmbId>" + 
	            		"</FinInstnId>" + 
	            		"</FIId>" + 
	            		"</Fr>" + 
	            		"<To>" + 
	            		"<FIId>" + 
	            		"<FinInstnId>" + 
	            		"<ClrSysMmbId>" + 
	            		"<MmbId>MEZNPKKA</MmbId>" + 
	            		"</ClrSysMmbId>" + 
	            		"</FinInstnId>" + 
	            		"</FIId>" + 
	            		"</To>" + 
	            		"<BizMsgIdr>20240125204930</BizMsgIdr>" + 
	            		"<MsgDefIdr>pacs.008.001.08</MsgDefIdr>" + 
	            		"<BizSvc>ACH</BizSvc>" + 
	            		"<CreDt>2024-05-23T15:40:30.087Z</CreDt>" + 
	            		"</AppHdr>" + 
	            		"<Document xmlns="+quotes+"urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08"+quotes+">" + 
	            		"<FIToFICstmrCdtTrf>" + 
	            		"<GrpHdr>" + 
	            		"<MsgId>Z20231218MUCBPKKABRTFMFB0901<"+slash+"MsgId>" + 
	            		"<CreDtTm>2024-05-24T09:20:00.070Z</CreDtTm>" + 
	            		"<BtchBookg>true</BtchBookg>" + 
	            		"<NbOfTxs>1</NbOfTxs>" + 
	            		"<TtlIntrBkSttlmAmt Ccy="+quotes+"PKR"+quotes+">200</TtlIntrBkSttlmAmt>" + 
	            		"<IntrBkSttlmDt>2024-05-24</IntrBkSttlmDt>" + 
	            		"<SttlmInf>" + 
	            		"<SttlmMtd>CLRG</SttlmMtd>" + 
	            		"</SttlmInf>" + 
	            		"</GrpHdr>" + 
	            		"<CdtTrfTxInf>" + 
	            		"<PmtId>" + 
	            		"<InstrId>Z20241218NCCPPKKABRTFMFB0194</InstrId>" + 
	            		"<EndToEndId>Z20241218NCCPPKKABRTFMFB0194</EndToEndId>" + 
	            		"<TxId>Z20241218NCCPPKKABRTFMFB0194</TxId>" + 
	            		"</PmtId>" + 
	            		"<PmtTpInf>" + 
	            		"<ClrChanl>RTNS</ClrChanl>" + 
	            		"<SvcLvl>" + 
	            		"<Prtry>0100</Prtry>" + 
	            		"</SvcLvl>" + 
	            		"<LclInstrm>" + 
	            		"<Prtry>CSDC</Prtry>" + 
	            		"</LclInstrm>" + 
	            		"<CtgyPurp>" + 
	            		"<Prtry>001</Prtry>" + 
	            		"</CtgyPurp>" + 
	            		"</PmtTpInf>" + 
	            		"<IntrBkSttlmAmt Ccy="+quotes+"PKR"+quotes+">200.0</IntrBkSttlmAmt>" + 
	            		"<IntrBkSttlmDt>2024-05-24</IntrBkSttlmDt>" + 
	            		"<ChrgBr>SLEV</ChrgBr>" + 
	            		"<InstgAgt>" + 
	            		"<FinInstnId>" + 
	            		"<ClrSysMmbId>" + 
	            		"<MmbId>NCCPPKKA</MmbId>" + 
	            		"</ClrSysMmbId>" + 
	            		"</FinInstnId>" + 
	            		"</InstgAgt>" + 
	            		"<InstdAgt>" + 
	            		"<FinInstnId>" + 
	            		"<ClrSysMmbId>" + 
	            		"<MmbId>MEZNPKKA</MmbId>" + 
	            		"</ClrSysMmbId>" + 
	            		"</FinInstnId>" + 
	            		"</InstdAgt>" + 
	            		"<Dbtr>" + 
	            		"<Nm>X</Nm>" + 
	            		"</Dbtr>" + 
	            		"<DbtrAcct>" + 
	            		"<Id>" + 
	            		"<Othr>" + 
	            		//"<Id>PK49MEZN0009810104546952</Id>" + 
	            		"<IBAN>PK49MEZN0009810104546952</IBAN>" +
	            		"</Othr>" + 
	            		"</Id>" + 
	            		"</DbtrAcct>" + 
	            		"<DbtrAgt>" + 
	            		"<FinInstnId>" + 
	            		"<ClrSysMmbId>" + 
	            		"<MmbId>NCCPPKKA</MmbId>" + 
	            		"</ClrSysMmbId>" + 
	            		"</FinInstnId>" + 
	            		"</DbtrAgt>" + 
	            		"<CdtrAgt>" + 
	            		"<FinInstnId>" + 
	            		"<ClrSysMmbId>" + 
	            		"<MmbId>MEZNPKKA</MmbId>" + 
	            		"</ClrSysMmbId>" + 
	            		"</FinInstnId>" + 
	            		"</CdtrAgt>" + 
	            		"<Cdtr>" + 
	            		"<Nm> MEEZAN Bank Ltd.</Nm>" + 
	            		"<Id>" + 
	            		"<PrvtId>" + 
	            		"<Othr>" + 
	            		"<Id>4550115683514</Id>" + 
	            		"<SchmeNm>" + 
	            		"<Prtry>CNIC</Prtry>" + 
	            		"</SchmeNm>" + 
	            		"</Othr>" + 
	            		"</PrvtId>" + 
	            		"</Id>" + 
	            		"</Cdtr>" + 
	            		"<CdtrAcct>" + 
	            		"<Id>" + 
	            		"<Othr>" + 
	            		//"<Id>PK39MEZN0012460104546951</Id>" + 
	            		"<Iban>PK39MEZN0012460104546951</Iban>" +
	            		"</Othr>" + 
	            		"</Id>" + 
	            		"</CdtrAcct>" + 
	            		/*"<InstrForCdtrAgt>" + 
	            		"<InstrInf>Pacs.008 message</InstrInf>" + 
	            		"</InstrForCdtrAgt>" + 
	            		"<Purp>" + 
	            		"<Prtry>033</Prtry>" + 
	            		"</Purp>" +*/
	            		"<InstrForNxtAgt>" + 
	            		"<InstrInf>/BNF/Beneficiary info</InstrInf>" + 
	            		"</InstrForNxtAgt>" + 
	            		"<InstrForNxtAgt>" + 
	            		"<InstrInf>/SMPL/Sample data</InstrInf>" + 
	            		"</InstrForNxtAgt>"+
	            		"<RmtInf>" + 
	            		"<Ustrd>Meezan Bank Ltd.</Ustrd>" + 
	            		"</RmtInf>" + 
	            		"</CdtTrfTxInf>" + 
	            		"</FIToFICstmrCdtTrf>" + 
	            		"</Document>" + 
	            		/*"<AppHdr xmlns="+quotes+"urn:iso:std:iso:20022:tech:xsd:head.001.001.01"+quotes+">" + 
	            		"<Fr>" + 
	            		"<FIId>" + 
	            		"<FinInstnId>" + 
	            		"<ClrSysMmbId>" + 
	            		"<MmbId>NCCPPKKA</MmbId>" + 
	            		"</ClrSysMmbId>" + 
	            		"</FinInstnId>" + 
	            		"</FIId>" + 
	            		"</Fr>" + 
	            		"<To>" + 
	            		"<FIId>" + 
	            		"<FinInstnId>" + 
	            		"<ClrSysMmbId>" + 
	            		"<MmbId>MEZNPKKA</MmbId>" + 
	            		"</ClrSysMmbId>" + 
	            		"</FinInstnId>" + 
	            		"</FIId>" + 
	            		"</To>" + 
	            		"<BizMsgIdr>20240125204930</BizMsgIdr>" + 
	            		"<MsgDefIdr>pacs.008.001.08</MsgDefIdr>" + 
	            		"<BizSvc>ACH</BizSvc>" + 
	            		"<CreDt>2024-05-24T09:20:00.087Z</CreDt>" + 
	            		"</AppHdr>" + */
	            		"</Body>" + 
	            		"</DataPDU> ")));
	           
	           
	             System.out.println("in method of doc::::: "+doc);
	              return doc;
	        } catch (ParserConfigurationException e) {
	        	System.out.println("in Parser Configuration Exception "+e.getMessage());
	            e.printStackTrace();
	        } catch (SAXException e) {
	        	System.out.println("in SAXException "+e.getMessage());
	            e.printStackTrace();
	        } catch (IOException e) {
	        	System.out.println("in IOException "+e.getMessage());
	            e.printStackTrace();
	        }
	
	        return doc;
	    }
	  
	  //public SignatureInfo verify(String dataPDU, boolean debugLog) throws Exception {
	  public String verify(String dataPDU, boolean debugLog) throws Exception {
		  System.out.println("In verify ");
		  StringBuilder sb = new StringBuilder();
			XPath xpath = XPathFactory.newInstance().newXPath();
			String xpathExpression = "//*[local-name()='Signature']";
			NodeList nodes = (NodeList) xpath.evaluate(xpathExpression, doc.getDocumentElement(), XPathConstants.NODESET);
			if (nodes == null || nodes.getLength() == 0)
				throw new Exception("Signature is missing in the document");
			Node nodeSignature = nodes.item(0);

			/*final KeySelector mockKeySelector = new KeySelector() {

				@Override
				public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {
							
					return new KeySelectorResult() {
						@Override
						public Key getKey() {
							//return signerCertificate.getPublicKey();
							return getPublicKeyByCert();
						}
					};
				}
			}; 
*/
			 System.out.println("In fac ");
			XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
			//DOMValidateContext valContext = new DOMValidateContext(keySelector, nodeSignature);    
			DOMValidateContext valContext = new DOMValidateContext(getPublicKeyByCert(), nodeSignature);
			 System.out.println("In valContext ");
			// Set up custom URIDereferencer to process Reference without URI.
			// This Reference points to element <Document> of MX message
			final NodeList docNodes = doc.getElementsByTagName("Document");
			 System.out.println("In Document ");
			final Node docNode = docNodes.item(0);
			 System.out.println("In docNode ");
			ByteArrayOutputStream refOutputStream = new ByteArrayOutputStream();
			System.out.println("In refOutputStream ");
			Transformer xform = TransformerFactory.newInstance().newTransformer();
			System.out.println("In xform ");
			xform.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			System.out.println("In setOutputProperty ");
			xform.transform(new DOMSource(docNode), new StreamResult(refOutputStream));
			System.out.println("In transform ");
			InputStream refInputStream = new ByteArrayInputStream(refOutputStream.toByteArray()); 
			System.out.println("In refInputStream ");
			valContext.setURIDereferencer(new NoUriDereferencer(refInputStream));
			System.out.println("In setURIDereferencer ");

			// Java 1.7.0_25+ complicates validation of ds:Object/QualifyingProperties/SignedProperties
			// See details at https://bugs.openjdk.java.net/browse/JDK-8019379
			//
			// One of the solutions is to register the Id attribute using the DOMValidateContext.setIdAttributeNS 
			// method before validating the signature 
			//String etsi="http://uri.etsi.org/01903/v1.3.2#";
			//NodeList nl = doc.getElementsByTagNameNS(etsi, "SignedProperties");
			
			NodeList nl = doc.getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SignedProperties");
			System.out.println("In nl ");
			if (nl.getLength() == 0)
				throw new Exception("SignerProperties is missing in signature");
			Element elemSignedProps = (Element) nl.item(0);
			System.out.println("In elemSignedProps ");
			
			valContext.setIdAttributeNS(elemSignedProps, null, "Id");
			System.out.println("In valContext ");
			
			XMLSignature signature = fac.unmarshalXMLSignature(valContext);
			System.out.println("In signature ");
			
			boolean coreValidity = signature.validate(valContext);
			System.out.println("In coreValidity ");
			if (coreValidity)
			{
				System.out.println("In if  ");
				// signature verified
			}
			else
			{
				System.out.println("In else  ");
				// signature verification failed
				System.out.println("Signature failed core validation");
			boolean sv = signature.getSignatureValue().validate(valContext);
				System.out.println("signature validation status: " + sv);
				// check the validation status of each Reference
				System.out.println("In check the validation status of each Reference  ");
			       Iterator i = signature.getSignedInfo().getReferences().iterator();
			   	System.out.println("In Iterator ");
			       for (int j=0; i.hasNext(); j++) {
			    	 	System.out.println("In for ");
			        	final Reference ref = (Reference) i.next();
			        	System.out.println("In ref ");
			        	final String refURI = ref.getURI();
			        	System.out.println("In refURI ");
			            	boolean refValid = ref.validate(valContext);
			            	System.out.println("In refValid ");
			            	System.out.println("ref["+j+"] validity status: " + refValid + ", ref URI: [" + refURI + "]");

			if (debugLog) {
			    String calcDigValStr = digestToString(ref.getCalculatedDigestValue());
			    String expectedDigValStr = digestToString(ref.getDigestValue());
			    System.out.println("    Calc Digest: " + calcDigValStr);
			    System.out.println("Expected Digest: " + expectedDigValStr);
			    //StringBuilder sb = new StringBuilder();
			    InputStream is = ref.getDigestInputStream();
			    InputStreamReader isr = new InputStreamReader(is);
			    BufferedReader br = new BufferedReader(isr);
			    String line;
			    while ((line = br.readLine()) != null) {
			        sb.append(line).append("\n");
			    }
			    is.close();
			    System.out.println("Transformed data: [" + sb.toString() + "]");
			  }

			        }
			}
				System.out.println("Transformed data: [" + sb.toString() + "]");
				
				
					return sb.toString();	
			}

	
		
		public static PublicKey getPublicKeyByCert() {
	        return getCertificate().getPublicKey();
	    }
	
		
		public static String getDatetime()
		{
			Date d = new Date();
	    	
	        TimeZone tz = TimeZone.getTimeZone("Asia/Karachi");
	        System.out.println("tz format: " + tz);
	        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
	        df.setTimeZone(tz);
	        String timestamp = df.format(new Date());
	        System.out.println("Current timestamp in ISO 8601 format: " + timestamp);
	        return timestamp;
	        
		}
		
		public static String getOnlyDate()
		{
			Date d = new Date();
	    	SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd");
	        String dateOnly = df.format(new Date());
	        System.out.println("Current Date in ISO 8601 format: " + dateOnly);
	        return dateOnly;
	        
		}
		
		private String getRAAST_PAYMENT_BIZ_MSG_ID() 
	    {
			NCSSAppDatabaseManager dbmanager;
			dbmanager = new NCSSAppDatabaseManager();
			dbmanager.connectToDB();
			String raastPaymentBizMsgId="";
			String Query = "SELECT 'NCCP'||''||KYCLIVE.RAAST_PAYMENT_BIZ_MSG_ID.NEXTVAL RAAST_PAYMENT_BIZ_MSG_ID FROM DUAL ";
			try {
				dbmanager.makeConnection();

				ResultSet rs = dbmanager.executeQuery(Query);

				while (rs.next()) {
					try {

						raastPaymentBizMsgId= rs.getString("RAAST_PAYMENT_BIZ_MSG_ID").trim();
						//raastPaymentBizMsgId = "NCCP"+raastPaymentBizMsgId;

					} catch (SQLException e) {

						e.printStackTrace();
					}
					System.out.println("raastPaymentBizMsgId is " + raastPaymentBizMsgId );
				}
			} catch (Exception ee) {

				ee.printStackTrace();
			}
			try {
				dbmanager.closeConnection();
			} catch (Exception e) {
				e.printStackTrace();
			}

			return raastPaymentBizMsgId;
		}

		
		private String getRAAST_PAYMENT_MSG_ID() 
	    {
			NCSSAppDatabaseManager dbmanager;
			dbmanager = new NCSSAppDatabaseManager();
			dbmanager.connectToDB();
			String raastPaymentMsgId="";
			String Query = "SELECT 'NCCPPKK'||''||KYCLIVE.RAAST_PAYMENT_MSG_ID.NEXTVAL RAAST_PAYMENT_MSG_ID FROM DUAL ";
			try {
				dbmanager.makeConnection();

				ResultSet rs = dbmanager.executeQuery(Query);

				while (rs.next()) {
					try {

						raastPaymentMsgId= rs.getString("RAAST_PAYMENT_MSG_ID").trim();
						//raastPaymentMsgId = "NCCPPKK"+raastPaymentMsgId;

					} catch (SQLException e) {

						e.printStackTrace();
					}
					System.out.println("raastPaymentMsgId is " + raastPaymentMsgId);
				}
			} catch (Exception ee) {

				ee.printStackTrace();
			}
			try {
				dbmanager.closeConnection();
			} catch (Exception e) {
				e.printStackTrace();
			}

			return raastPaymentMsgId;
		}
		
/*		
		"<EndToEndId>NCC2024000000001111NCCPPKK05</EndToEndId>" +
*/

		private String getRAAST_PAYMENT_INSTRUCTION_ID() 
	    {
			NCSSAppDatabaseManager dbmanager;
			dbmanager = new NCSSAppDatabaseManager();
			dbmanager.connectToDB();
			String raastPaymentInstrId="";
			String Query = "SELECT 'NCCP'||''||KYCLIVE.RAAST_PAYMENT_INSTR_ID.NEXTVAL RAAST_PAYMENT_INSTR_ID FROM DUAL ";
			try {
				dbmanager.makeConnection();

				ResultSet rs = dbmanager.executeQuery(Query);

				while (rs.next()) {
					try {

						raastPaymentInstrId= rs.getString("RAAST_PAYMENT_INSTR_ID").trim();
						//raastPaymentInstrId = "NCCP"+raastPaymentInstrId;

					} catch (SQLException e) {

						e.printStackTrace();
					}
					System.out.println("raastPaymentInstrId is " + raastPaymentInstrId);
				}
			} catch (Exception ee) {

				ee.printStackTrace();
			}
			try {
				dbmanager.closeConnection();
			} catch (Exception e) {
				e.printStackTrace();
			}

			return raastPaymentInstrId;
		}
		
		private String getRAAST_PAYMENT_ENDTOEND_ID() 
	    {
			NCSSAppDatabaseManager dbmanager;
			dbmanager = new NCSSAppDatabaseManager();
			dbmanager.connectToDB();
			String raastPaymentEndtoEndId="";
			String Query = "SELECT 'NCCP'||''||KYCLIVE.RAAST_PAYMENT_ENDTOEND_ID.NEXTVAL RAAST_PAYMENT_ENDTOEND_ID FROM DUAL ";
			try {
				dbmanager.makeConnection();

				ResultSet rs = dbmanager.executeQuery(Query);

				while (rs.next()) {
					try {

						raastPaymentEndtoEndId= rs.getString("RAAST_PAYMENT_ENDTOEND_ID").trim();
						//raastPaymentEndtoEndId = "NCCP"+raastPaymentEndtoEndId;

					} catch (SQLException e) {

						e.printStackTrace();
					}
					System.out.println("raastPaymentEndtoEndId is " + raastPaymentEndtoEndId);
				}
			} catch (Exception ee) {

				ee.printStackTrace();
			}
			try {
				dbmanager.closeConnection();
			} catch (Exception e) {
				e.printStackTrace();
			}

			return raastPaymentEndtoEndId;
		}
}
