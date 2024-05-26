package bulkIbanRaastTesting;

import org.json.XML;
import org.json.simple.*;
import org.json.simple.parser.JSONParser;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.json.JSONObject;

import java.rmi.RemoteException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Hashtable;


import javax.ejb.EJBHome;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.rmi.PortableRemoteObject;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import weblogic.logging.NonCatalogLogger;
import com.nccpl.gen.dao.NCSSAppDatabaseManager;
import com.nccpl.rms.logging.Level;
import com.ncss.client.template.NCSSErrorMsg;
import com.ncss.client.utils.UtilWebBean;
import com.ncss.common.ErrorNumber;
import javax.xml.crypto.dsig.XMLSignature;

import com.ncss.common.NCSSException;

import com.ncss.server.core.CoreBusiness;
import com.ncss.server.core.CoreBusinessHome;
import com.ncss.server.utils.ncssUtil.NcssUtil;
import com.ncss.server.utils.ncssUtil.NcssUtilHome;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import com.nccpl.Kyc.CreateJWTToken;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Time;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Hashtable;

import com.nccpl.gen.dao.NCSSAppDatabaseManager;
import weblogic.logging.NonCatalogLogger;

import com.ncss.client.utils.UtilWebBean;
import com.ncss.common.Global;
import com.ncss.common.TableRow;

import com.ncss.server.core.CoreBusiness;
import com.ncss.server.core.CoreBusinessHome;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
/*import java.security.Signature;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.net.ssl.HttpsURLConnection;
import javax.rmi.PortableRemoteObject;*/
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
//import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;
import org.apache.commons.codec.binary.Base64;
import com.nccpl.gen.dao.NCSSAppDatabaseManager;
import com.nccpl.rms.logging.Level;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.io.File;
import java.io.IOException;
import java.net.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.sql.ResultSet;
import java.sql.SQLException;
import com.ncss.server.business.DigitalPayment.DigitalPaymentHomeSession;
import com.ncss.server.business.DigitalPayment.DigitalPaymentSession;

public class DigitalPayment {
	

	private NonCatalogLogger logger;
	private NCSSAppDatabaseManager dbmanager;
	private UtilWebBean utilWBean;	
	
	
	//private String date = null;
	private String uin = null;
	private String iban = null;
	private String type = null;
	//private String iban_name = null;
	private String bank_code = null;
	String sign = null;
	List<XMLObject> sign1 = null;
	
	
	private String CONTENT_TYPE=null;
	private String ACCEPT=null;
	private String SENDER_PART_CODE=null;
	private String SENDER_USER_CODE=null;
	private String RECEIVER_USER_CODE=null;
	private String USERNAME=null;
	private String PASS=null;
	
	
	
	private String Batch_ID=null;
	private String Instruction_ID=null;
	private String RequestID=null;
	String dataPDU = null;
	//Map dataPDU = null;

	private String payload,Authorization,RPC=null;
	
	Document w3cDoc = null;
    
	
	NcssUtilHome utilityHome = null;
	NcssUtil utility = null;
	/**
	    * The initial context of the session bean
	    */
	    private Context	ctx	=	null;
		
		
		
		private EJBHome home=null;
	  	
	private String elementId = "";
	private String IP="",PORT="",USER="",URL="",PASSWORD="";
	private String srvDate="",srvTime="";	
	CoreBusiness core =	null;//CoreBusiness Session Bean Remote Interface variable which implements all core business logic methods
	CoreBusinessHome coreHome =	null;//CoreBusiness Session Bean Home Interface variable which implements all core business logic methods
	NcssUtilHome utilHome = null;
    NcssUtil ncssUtilRemote	= null;
	ArrayList rowList = null , returnedList = null;	
	String isUsersIdReadOnly = "yes"; //isUsersIdReadOnly
	int	returnValue=0; //variable used in function getPageResult to to return result
	String tableName = "";

	public DigitalPayment() 
	{	logger = new NonCatalogLogger("Digital_Payment.....");
		logger.debug("////////////////////////Digital_Payment////////////////////////////");
		utilWBean=new UtilWebBean();
		dbmanager=new NCSSAppDatabaseManager();		
	}
	private void log(short level, String logString) {
		switch (level) {
		case ErrorNumber.LVL_DEBUG:
			logger.debug(logString);
			break;
		case ErrorNumber.LVL_INFO:
			logger.info(logString);
			break;
		case ErrorNumber.LVL_WARNING:
			logger.warning(logString);
			break;
		default:
			logger.error(logString);
			break;
		}
	}
	
	
	public int getPageResult(HttpServletRequest request, HttpServletResponse response, HttpSession session)
	  {
	    String Response = "";
	    System.out.println( ":::::::::: ENTERD IN api calling bean:::::::::::");
	    this.core = getCoreBusinessRemoteObject();
	    String strOpCode = "";
	    String strTrCode = (String)session.getAttribute("trnCode");

	   	HttpSession session1 = request.getSession();
	    this.elementId = ((String)session1.getValue("elementId"));
	    System.out.println( ":::::::::: session1 elementId: " + this.elementId + " ::::::::");
	    try
	    {
	      strOpCode = request.getParameter("opCode");
	      System.out.println( ":::::::::: OPERATION CODE IS : " + strOpCode + " :::::::::::");
	    }
	    catch (Exception e)
	    {
	      this.utilWBean.printLog("exception getting operation\tcode...");
	    }
	    

	    if (strOpCode.equals("101"))
	    {
	      System.out.println( ":::::::::: 101 CALLED ::::::::::");

	     // getRequest(request, this.userId, strTrCode, this.terminalId, this.reason);

	      String res = null;
	      String reqStatus = "S";

	      this.returnValue = 1;
	    
	      logger.debug( ":::::::::: ENTERD IN api calling bean:::::::::::");
			 
			String  Code="";
			returnValue = 0;
			core = getCoreBusinessRemoteObject();
			 
				 
					//String reqMSG="SUCCESSFUL";
					returnValue=1;
						
						try {
							
							PreVal_API_call();
							//PreVal_API_call_1();
								{
								 logger.debug( "before sendcall ::: ");
									  try{
										  //res = DigitalPaymentRemoteInterface.sendcall(payload,Authorization,RequestID,SENDER_PART_CODE,SENDER_USER_CODE,RPC, URL,CONTENT_TYPE,ACCEPT, w3cDoc.toString());
										  //res = DigitalPaymentRemoteInterface.sendcall(payload,Authorization,RequestID,SENDER_PART_CODE,SENDER_USER_CODE,RPC, URL,CONTENT_TYPE,ACCEPT, sign);
										//  res = DigitalPaymentRemoteInterface.sendcall(payload,Authorization,RequestID,SENDER_PART_CODE,SENDER_USER_CODE,RPC, URL,CONTENT_TYPE,ACCEPT, dataPDU);
										
										  //open this tag
										  //res = DigitalPaymentRemoteInterface.sendcall(payload,Authorization,RequestID,SENDER_PART_CODE,SENDER_USER_CODE,RPC, URL,CONTENT_TYPE,ACCEPT, dataPDU);
										  									
									  	}
									  catch(Exception ex)
									  {
										  res=ex.getMessage();
									  }
									  logger.debug( "after sendcall" +res);
								    
								}
								
								
								//decode response
								
								/* String[] err = res.split(":");
							     Code=err[0];
							     Response = err[1];
							     
							     logger.debug( "after sendcall Code is " +Code);
							     logger.debug( "after sendcall Response is " +Response);
								    String[] split_string = Response.split("\\.");
							        String base64EncodedHeader = split_string[0];
							        String base64EncodedBody = split_string[1];
							        String base64EncodedSignature = split_string[2];
							        
								 String DecodedResString=new String(DatatypeConverter.parseBase64Binary(base64EncodedBody));
								 logger.debug("after sendcall DecodedResString " +DecodedResString);
								String finalString="";
								 try{
								 Object obj = new JSONParser().parse(DecodedResString.trim());
							     JSONObject jo = (JSONObject)obj;
							     Long statusCode = (Long)jo.get("statusCode");
							     String description = (String)jo.get("description");
							   
							     logger.debug("after sendcall statusCode" +statusCode);
							     logger.debug("after sendcall description" +description);
								 
								  finalString=statusCode+":"+description;
									 log(Level.INFO, "after sendcall finalString" +finalString);
									 
								 }
								 catch(Exception ex)
								 {
									 logger.debug( "after sendcall " +ex.toString());
								 }
								 
							if (Integer.valueOf(Code)!=200)
							{
								reqStatus="F";
								//reqMSG="FAILED";
								returnValue=0;
							}*/
							//insert into table
							
							 //ArrayList returnedList=  UpdateMainTable(reqStatus, Integer.valueOf(Code), finalString, RequestID);
							

							
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					 //update request status
			 
	    }

	    
	    if (strOpCode.equals("102"))
	    {
	      System.out.println( ":::::::::: 102 CALLED ::::::::::");

	      String res = null;
	      String reqStatus = "S";

	      this.returnValue = 1;
	    
	      logger.debug( ":::::::::: ENTERD IN api calling bean:::::::::::");
			 
			String  Code="";
			returnValue = 0;
			core = getCoreBusinessRemoteObject();
			 
					returnValue=1;
						
						try {
							
							PreVal_API_call_1();
								{
								 logger.debug( "before sendcall ::: ");
									  try{
										  //open this tag
										  res = DigitalPaymentRemoteInterface.sendcall(payload,Authorization,RequestID,SENDER_PART_CODE,SENDER_USER_CODE,RPC, URL,CONTENT_TYPE,ACCEPT, dataPDU);
										  									
									  	}
									  catch(Exception ex)
									  {
										  res=ex.getMessage();
									  }
									  logger.debug( "after sendcall" +res);
								    
								}
								
								
							
							
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					 //update request status
			 
	    }
	
	      
	       logger.debug("returnValue is "+returnValue); 
				return returnValue;
				

			
	  }
/*
	public int Pre_val_IBAN(String uin, String date, String iban, String type, String name)
	{	
		logger.debug( ":::::::::: ENTERD IN api calling bean:::::::::::");
		String Response = "";
		String  Code="";
		returnValue = 0;
		Demo02 demo = new Demo02();
		core = getCoreBusinessRemoteObject();
		 {
			 String res="";
				String reqStatus="S";
				//String reqMSG="SUCCESSFUL";
				returnValue=1;
					
					try {
						
						//PreVal_API_call(uin, date, iban, type, name);
						PreVal_API_call();
						// ArrayList returnedList1=  InsertMainTable( RECEIVER_USER_CODE,SENDER_PART_CODE,Batch_ID,reqStatus);
						 //if (Integer.parseInt((String) returnedList1.get(0)) == 1) 
							{
							 logger.debug( "before sendcall");
								  try{
									  
									   
							            
									  //res = RAASTRemoteInterface.sendcall(payload,Authorization,RequestID,SENDER_PART_CODE,SENDER_USER_CODE,RPC, URL,CONTENT_TYPE,ACCEPT);
							            res = DigitalPaymentRemoteInterface.sendcall(payload,Authorization,RequestID,SENDER_PART_CODE,SENDER_USER_CODE,RPC, URL,CONTENT_TYPE,ACCEPT, w3cDoc.toString());
									  
									  
								  	}
								  catch(Exception ex)
								  {
								 res=ex.getMessage();
								  }
								  logger.debug( "after sendcall" +res);
							    
							}
							
							
							//decode response
							/*
							 String[] err = res.split(":");
						     Code=err[0];
						     Response = err[1];
						     
						     logger.debug( "after sendcall Code is " +Code);
						     logger.debug( "after sendcall Response is " +Response);
							    String[] split_string = Response.split("\\.");
						        String base64EncodedHeader = split_string[0];
						        String base64EncodedBody = split_string[1];
						        String base64EncodedSignature = split_string[2];
						        
							 String DecodedResString=new String(DatatypeConverter.parseBase64Binary(base64EncodedBody));
							 logger.debug("after sendcall DecodedResString " +DecodedResString);
							String finalString="";
							 try{
							 Object obj = new JSONParser().parse(DecodedResString.trim());
						     JSONObject jo = (JSONObject)obj;
						     Long statusCode = (Long)jo.get("statusCode");
						     String description = (String)jo.get("description");
						   
						     logger.debug("after sendcall statusCode" +statusCode);
						     logger.debug("after sendcall description" +description);
							 
							  finalString=statusCode+":"+description;
								 log(Level.INFO, "after sendcall finalString" +finalString);
								 
							 }
							 catch(Exception ex)
							 {
								 logger.debug( "after sendcall " +ex.toString());
							 }
							 
						if (Integer.valueOf(Code)!=200)
						{
							reqStatus="F";
							//reqMSG="FAILED";
							returnValue=0;
						}
						//insert into table
						
						 ArrayList returnedList=  UpdateMainTable(reqStatus, Integer.valueOf(Code), finalString, RequestID);
						*

						
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				 //update request status
				
			}
			 
			

		logger.debug("returnValue is "+returnValue); 
		return returnValue;
	}
	
	*/
	
	private CoreBusiness getCoreBusinessRemoteObject() {
		core = null;
		coreHome = (CoreBusinessHome) utilWBean.getHomeObject("com.ncss.server.core.CoreBusinessHome");
		if (coreHome == null) {
			utilWBean.printLog("Null pointer Exception");
			return (core = null);
		}

		try {
			core = (CoreBusiness) coreHome.create();
		} catch (Exception ee) {
			utilWBean.printLog(ee.getMessage());
			return (core = null);
		}
		return core;
	}

	
	
	private void printLog(String logString) {
		try {
			logger.debug(logString);
			logger.debug("\n");
		} catch (Exception e) {
			System.out.println("Error Writting In File :::::::::::::::"
					+ e.getMessage());
		}
	}
	
	/**
	* initializes NcssUtil remote object
	* @return void
	*/
	private void getUtilityRemote()
	{
		utilityHome=null;
		utility=null;
		utilityHome	=(NcssUtilHome)getHomeObject("com.ncss.server.utils.ncssUtil.ncssUtilHome");
		if(utilityHome==null)
		{
			printLog("getUtilityHome(), utilityHome is null");
			utility = null;
		}
		else
		{
			try
			{
				utility=(NcssUtil)utilityHome.create();			
			}
			catch(Exception ee )
			{
				logger.debug("getUtilityRemote(), exception in utilityHome.create() " + ee);
				utility = null;			
			}
		}
		printLog("getUtilityRemote(), utility is " + utility); 
	}
	/**
	* looks up a bean by using JNDI name passed to it and returns EJBHome object.
	* @param strJndi JNDI name of the bean
	* @return EJBHome object
	*/
	private EJBHome getHomeObject(String strJndi)
  	{
		try
		{
			ctx = getInitialContext();
			home = (EJBHome) ctx.lookup(strJndi);
			return home;
		}
		catch (NamingException ne)
		{
			printLog("exception in getHomeObject " + ne);
			return (home=null);
		}
	}
	/**
	    * gets initial context for session bean before look up
	    */
	    private Context getInitialContext() throws NamingException
		{
		    return new InitialContext();
	  	}
	    
	    public ArrayList InsertMainTable(String RECEIVER_PARTICIPANT_CODE,String BATCH_INITIATIOR,String BATCH_ID,String reqStatus)
	    {

	    	String insertQuery = null;
	    	StringBuffer sb=new StringBuffer();
	    
	    	
	    		    	
	    	
	    	sb.append("INSERT INTO KYCLIVE.RAAST_API_SEND_INSTRUCTION ( ");
	    	sb.append("		   API_REQUEST_ID, SENDER_PARTICIPANT_CODE, SENDER_USER_CODE,  ");
	    	sb.append("			   RECEIVER_PARTICIPANT_CODE, BATCH_INITIATIOR, BATCH_ID,  ");
	    	sb.append("			   VALUEDATE, INSTRUCTION_ID, IDENTIFICATION_TYPE,  ");
	    	sb.append("			   IDENTIFICATION_NO, IBAN,REQUEST_DATETIME,READ_WRITE_FLAG) ");
	    	sb.append("			VALUES ('"+RequestID+"', ");
	    	sb.append("			'"+SENDER_PART_CODE+"', ");
	    	sb.append("		 '"+SENDER_USER_CODE+"', ");
	    	sb.append("					'"+RECEIVER_PARTICIPANT_CODE+"', ");
	    	sb.append("			'"+BATCH_INITIATIOR+"', ");
	    	sb.append("			'"+BATCH_ID+"', ");
	    	sb.append("			  (SELECT SYSTEM_DATE FROM SYSTEM), ");
	    	sb.append("			'"+Instruction_ID+"', ");
	    	sb.append("			'"+type+"', ");
	    	sb.append("			 '"+uin+"', ");
	    	sb.append("		 '"+iban+"' ,CURRENT_TIMESTAMP,'W')");	    	    
	    	
	    	
	    	insertQuery = sb.toString();
	    	log(Level.INFO, ":::::::::: insert  query ==== ::::::::::"
	    			+ insertQuery);

	    	
	    	ArrayList res = null;

	    	try {
	    		res=core.executeUpdate(insertQuery, CoreBusiness.TRANSACTION);
	    	} catch (RemoteException e) {
	    		// TODO Auto-generated catch block
	    		e.printStackTrace();
	    	} catch (NCSSException e) {
	    		// TODO Auto-generated catch block
	    		e.printStackTrace();
	    	}
	    	
	    	return res;
	    	
	    }
	    public ArrayList UpdateMainTable(String REQUEST_STATUS,int RESPONSEE_STATUS,String REJECT_REASON,String api_request_id)
	    {

	    	String insertQuery = null;
	    	StringBuffer sb=new StringBuffer();
	    
	    	
	    		    	
	    	
	    	sb.append("UPDATE  KYCLIVE.RAAST_API_SEND_INSTRUCTION set  REQUEST_STATUS= '"+REQUEST_STATUS+"',  RESPONSE_DATETIME=CURRENT_TIMESTAMP,  " +
	    			"     RESPONSEE_STATUS = '"+RESPONSEE_STATUS+"',      REJECT_REASON= '"+REJECT_REASON+"'  where api_request_id='"+api_request_id+"'  ");
	    	
	    	
	    	
	    	insertQuery = sb.toString();
	    	logger.debug(":::::::::: update  query ==== ::::::::::"
	    			+ insertQuery);

	    	
	    	ArrayList res = null;

	    	try {
	    		res=core.executeUpdate(insertQuery, CoreBusiness.TRANSACTION);
	    	} catch (RemoteException e) {
	    		// TODO Auto-generated catch block
	    		e.printStackTrace();
	    	} catch (NCSSException e) {
	    		// TODO Auto-generated catch block
	    		e.printStackTrace();
	    	}
	    	
	    	return res;
	    	
	    }
	  
	    
	    
	    private  void PreVal_API_call_1()
	    {  logger.debug("inside verification  " );
	    getUtilityRemote();
	    int ResponceCode=0;
	    	String returnValue="0";
		try
		{
			
		
			logger.debug("getting Header Info from DB "  );
			
			//getHeaderInfo();
			getipPort();	
			   
			logger.debug("inside RAASTVerification ");
			logger.debug(" CONTENT_TYPE::: " +CONTENT_TYPE  + " ACCEPT " +ACCEPT + " SENDER_PART_CODE " +SENDER_PART_CODE + " SENDER_USER_CODE " +SENDER_USER_CODE + " USERNAME " +USERNAME + " PASS " +PASS );

		  String authString = USERNAME + ":" + PASS;
		  logger.debug("inside RAASTVerification  authString " +authString );
	        
	      byte[] encodedBytes = Base64.encodeBase64(authString.getBytes());		
	      String authStringEnc = new String(encodedBytes);
	      logger.debug("inside RAASTVerification  authorization Encoded String is::::::: " +authStringEnc );
	      
	    
	      String iss="NCCPPKKASNRT" ; 
  	      /*String iat = "2024012510" ; //1970-01-01T00:00:00Z UTC
  	      String exp = "2024012522";*/
	      String iat = "1705032119" ; //1970-01-01T00:00:00Z UTC
  	      String exp = "1753053041"; 
  	      String asrvType = "client"; 
  	      //String certIss = "CN=test-TST-AD-CA,DC=test,DC=mpg,DC=local" ;
  	      	String certIss = "CN=test-TST-AD-CA,DC=test,DC=mpg,DC=local";
  	      //String certIss = "cn=nccppkkasnrt,o=nccpl,c=pk" ;
  	     // String certIss = "CN=NCCPPKKASNRT,OU=Payment Department,O=NCCPL,L=KARACHI,S=SINDH,C=PK";
  	     // String certIss = "CN=NCCPPKKASNRT,O=NCCPL,C=PK";
  	    //String certIss = "C=PK, O=State Bank of Pakistan, OU=MPG System, CN=SBP MPG Web Services Access
  	    //String certIss = "CN=SBP MPG Web Services Access,O=State Bank of Pakistan,C=PK";
  	    //  String certSN = "6c 00 00 05 e6 20 97 ab 6d f4 d4 bb fe 00 01 00 00 05 e6";
  	      String certSN = "6C 00 00 05 E6 20 97 AB 6D F4 D4 BB FE 00 01 00 00 05 E6";
  	     

  	     	//get batch id , request ID and instruction ID
					
			RequestID= String.valueOf(utility.getSequenceNumber("RAAST_REQUEST_ID"));
			logger.debug("inside RAASTVerification  RequestID     ::::::::::::::::: " +RequestID );
			
			
			String res=  createJWTAndSign(iss, iat, exp, asrvType, certIss, certSN);		
			logger.debug("token generated  ===== " + res); 
		 	  
			 logger.debug("Authorization is ===== " + Authorization);
			 logger.debug("RequestID is ===== " + RequestID);
			 logger.debug("URL is ===== " + URL);
			 
			 URL = URL+"/"+RequestID;
			 
			 logger.debug("Final URL with Request Id is ===== " + URL);
			 
			 logger.debug(" before make connection");
			
				
					  createRAASTServerConnection();
					  logger.debug("after make connection");	 
					  payload=res;
					  logger.debug("final token created from claims "+payload);	 
					  Authorization="Bearer "+payload+"";
					  logger.debug("Authorization from claims "+Authorization);	 
					  
					 
					  	sampleExample mx = new sampleExample();
					  	w3cDoc = mx.getW3cDoc();
					  	//Document doc= mx.sign(w3cDoc, mx.getCertificate(), mx.getPrivateKey(), true);
					  	String doc= mx.sign(w3cDoc, mx.getCertificate(), mx.getPrivateKey(), true);
					    logger.debug( "after sign is ===== "+doc.toString());
					    //SignatureInfo si = mx.verify(doc.toString(), true);
					    sign =  mx.verify(doc.toString(), true);
					    logger.debug( "after verify sign is ===== "+mx.verify(doc.toString(), true));
					    
					    // Initialising search string
			            String subst = new String("DataPDU");
			            String finalDocSign = "<"+doc.substring(doc.indexOf(subst), doc.length()); 
			            System.out.print("sign is "+sign);
			            System.out.print("finalDocSign is "+finalDocSign);
			            
					    //String traceReference="0eecaf02-2301-4638-bb96-b67973c57940";
			            String traceReference=getRAAST_PAYMENT_TRACE_REF(); 
			            String service = "N";
			            String type ="pacs.008.001.08";
			           
			            
			             dataPDU = JSONResponse(traceReference,service, type, SENDER_USER_CODE, "SBPPPKKAXIPS", finalDocSign.toString());
			            logger.debug( "dataPDU is ===== " +dataPDU.toString());
			           
			         
		}
		catch(Exception ex)
		{
			 returnValue="0";
			 logger.debug("Exception in generating request is ===== " + ex.getMessage());
		
			
		}
		
	    }
	    
	    
	    //private  void PreVal_API_call(String uin, String date, String iban, String type, String iban_name)
	    private  void PreVal_API_call()
	    {  logger.debug("inside RAASTVerification  " );
	    getUtilityRemote();
	    int ResponceCode=0;
	    	String returnValue="0";
		try
		{
			
		
			logger.debug("getting Header Info from DB "  );
			
			//getHeaderInfo();
			getipPort();	
			   
			logger.debug("inside RAASTVerification ");
			logger.debug(" CONTENT_TYPE::: " +CONTENT_TYPE  + " ACCEPT " +ACCEPT + " SENDER_PART_CODE " +SENDER_PART_CODE + " SENDER_USER_CODE " +SENDER_USER_CODE + " USERNAME " +USERNAME + " PASS " +PASS );

		  String authString = USERNAME + ":" + PASS;
		  logger.debug("inside RAASTVerification  authString :::: " +authString );
	        
	      byte[] encodedBytes = Base64.encodeBase64(authString.getBytes());		
	      String authStringEnc = new String(encodedBytes);
	      logger.debug("inside RAASTVerification  authorization Encoded String is::::::: " +authStringEnc );
	      
	      String iss="NCCPPKKASNRT" ; 
  	      /*String iat = "2024012510" ; //1970-01-01T00:00:00Z UTC
  	      String exp = "2024012522";*/
	      String iat = "1705032119" ; //1970-01-01T00:00:00Z UTC
  	      String exp = "1753053041"; 
  	      String asrvType = "client"; 
  	      String certIss = "CN=test-TST-AD-CA,DC=test,DC=mpg,DC=local" ;
  	      //String certIss = "cn=nccppkkasnrt,o=nccpl,c=pk" ;
  	     // String certIss = "CN=NCCPPKKASNRT,OU=Payment Department,O=NCCPL,L=KARACHI,S=SINDH,C=PK";
  	     // String certIss = "CN=NCCPPKKASNRT,O=NCCPL,C=PK";
  	    //String certIss = "C=PK, O=State Bank of Pakistan, OU=MPG System, CN=SBP MPG Web Services Access
  	    //String certIss = "CN=SBP MPG Web Services Access,O=State Bank of Pakistan,C=PK";
  	      String certSN = "6C000005E62097AB6DF4D4BBFE0001000005E6"; 
  	     
		 
  	      
	      //Authorization="Basic "+authStringEnc+"";
			 //SPC=SENDER_PART_CODE;
			// SUC=SENDER_USER_CODE;
			
		 
			//get batch id , request ID and instruction ID
					
			RequestID= String.valueOf(utility.getSequenceNumber("RAAST_REQUEST_ID"));
			logger.debug("inside RAASTVerification  RequestID " +RequestID );
			
			
			//String res= CreateJWTToken.createJWTAndSign(SENDER_PART_CODE, Batch_ID,date, Instruction_ID, iban, iban_name,type,uin,"PKR", "1.00", "033");
			String res=  createJWTAndSign(iss, iat, exp, asrvType, certIss, certSN);		
			logger.debug("token generated  ===== " + res); 
		 	
		    /*RPC=getReceiverBIC(bank_code);
			 RECEIVER_USER_CODE=RPC;*/
			  
			 logger.debug("Authorization is ===== " + Authorization);
			 logger.debug("RequestID is ===== " + RequestID);
			 logger.debug("URL is ===== " + URL);
			 
			 URL = URL+"/"+RequestID;
			 
			 logger.debug("Final URL with Request Id is ===== " + URL);
			 
			 logger.debug(" before make connection");
			
				
					  createRAASTServerConnection();
					  logger.debug("after make connection");	 
					  payload=res;
					  logger.debug("final token created from claims "+payload);	 
					  Authorization="Bearer "+payload+"";
					  logger.debug("Authorization from claims "+Authorization);	 
					  
					   /*Demo02 demo = new Demo02();
					  
					    Document w3cDoc = demo.getW3cDoc();
			            System.out.println("after w3c :::: "+w3cDoc);
			            logger.debug("after w3c ::::::::: "+w3cDoc);	 
			            
			            PrivateKey privateKey = demo.getPrivateKey();
			            System.out.println("after privtateKey");
			            logger.debug("after privtateKey ::::: "); 
			            
			            System.out.println("before signedInfo");
			            SignedInfo signedInfo = demo.getSignedInfo(demo.getAllReference());
			            System.out.println("after signedInfo");
			            logger.debug("after signedInfo"); 
			            
			            KeyInfo keyInfo = demo.getKeyInfo();
			            System.out.println("after keyinfo");
			            logger.debug("after keyinfo"); 
			           
			            sign = demo.sign(w3cDoc, privateKey, signedInfo, keyInfo);
			            logger.debug("after sign"); */
			            
			           //sign1 = demo.signedInfo(w3cDoc, privateKey, signedInfo, keyInfo);
			           // System.out.println(sign1); 
			            //sign = demo.sign(w3cDoc, privateKey, signedInfo, keyInfo);
					  
					  	Demo02 demo = new Demo02();
					  
					    Document w3cDoc = demo.getW3cDoc();
			            System.out.println("after w3c :::: "+w3cDoc);
			            //PrivateKey privateKey = demo.getPrivateKey();
			            //System.out.println("after privtateKey");
			            KeyInfo keyInfo = demo.getKeyInfo();
			            System.out.println("after keyinfo");
			        
			           // SignedInfo signedInfo = demo.getSignedInfo(demo.getAllReference());
			            //SignedInfo signedInfo = demo.getSignedInfo(demo.getListReference());
			            System.out.println("after signedInfo");
			           
			          
			            
			           // sign = demo.signedInfo(w3cDoc, demo.getMySignedInfo(), keyInfo);
			            sign = demo.signedInfo(w3cDoc, demo.getMySignedInfo());
			           
			            System.out.println("after sign");
			           
			             // Initialising search string
			            String subst = new String("DataPDU");
			     
			            
			            sign = "<"+sign.substring(sign.indexOf(subst), sign.length()); 
			            
			            //sign="<"+sign.indexOf(subst),sign.length();
			            System.out.print("sign is "+sign);
			            
			            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
				        DocumentBuilder builder = null;
				        Document document = null;
				        try
				        {
				        	builder  = factory.newDocumentBuilder();
				        	document = builder.parse(new InputSource(new StringReader(sign)));
				        }
				        catch(Exception ex)
				        {
				        	 System.out.print("Exception is "+ex);
				        }
					  	/*Demo02 demo = new Demo02();
					  	Document w3cDoc = demo.getW3cDoc();
			            System.out.println("after w3c :::: "+w3cDoc);
			            logger.debug("after w3c ::::::::: "+w3cDoc);
			            
					  	MCXDocument mx = new MCXDocument();*/
					  	//XMLSignature sign = mx.MCXDocument(w3cDoc);
					  	//String sign = mx.MCXDocument(w3cDoc);
			            String traceReference="0eecaf02-2301-4638-bb96-b67973c57940";
			            String service = "N";
			            String type ="pacs.008.001.08";
			           
			            
			           // dataPDU =  JSONResponse(traceReference,service, type, SENDER_USER_CODE, "MUCBPKKKRTG", sign);
			             //dataPDU = JSONResponse(traceReference,service, type, SENDER_USER_CODE, "MUCBPKKKRTG", sign.toString());
			            dataPDU = JSONResponse(traceReference,service, type, SENDER_USER_CODE, "MUCBPKKKRTG", sign.toString());
			            //logger.debug( "dataPDU is ===== " +(new JSONParser().parse(dataPDU.toString()) ));
			            logger.debug( "dataPDU is ===== " +dataPDU.toString());
			           
			            
			           //String  dataPDUToken = createJWTJSON(traceReference,service, type, SENDER_USER_CODE, "MUCBPKKKRTG", sign);
			            //logger.debug( "dataPDUToken after JWT token is ===== " +dataPDUToken);
			            //dataPDU=dataPDU.replaceAll("\\", "");
			            
			        /*    getSetMethod  docParam = new getSetMethod();
			            docParam.setTraceReference("traceReference");
				    	docParam.setService(service);
				    	docParam.setType(type);
				    	docParam.setSENDER_USER_CODE(SENDER_USER_CODE);
				    	docParam.setRECEIVER_USER_CODE(RECEIVER_USER_CODE);
				    	docParam.setSign(sign);
				    	
				    	System.out.println(new Gson().toJson(docParam));  
			         */
		}
		catch(Exception ex)
		{
			 returnValue="0";
			 logger.debug("Exception in generating request is ===== " + ex.getMessage());
		
			
		}
		
	    }
	    //original 
		/* 
		public String JSONResponse1(String traceReference,String service, String type, String sender, String receiver, String DataPDU)	throws Exception 
	    {
			logger.debug("DataPDU in JSON Response :::: "+DataPDU);
			JSONObject obj = new JSONObject();
			//Map map = new LinkedHashMap();
			LinkedHashMap<String, Object> map = new LinkedHashMap<String, Object>();
				
			map.put("traceReference",traceReference);
			map.put("service",service);
			map.put("type",type);
			map.put("sender",sender);
			map.put("receiver",receiver);
			map.put("document",DataPDU);
		
			String jsonText =  obj.toJSONString(map);
			
			
			logger.debug("Generating JWT JSON token..........."+jsonText ); 
			
			return jsonText;
		
	    } */
	    
	    
	    
	    ;
		public String JSONResponse(String traceReference,String service, String type, String sender, String receiver, String DataPDU)	throws Exception 
	    {
			logger.debug("DataPDU in JSON Response :::: "+DataPDU);
			
			DataPDU=DataPDU.replace("\"","'");
			logger.debug("After replace fn for double quotes:::::::::::::: "+DataPDU);
			
			org.json.simple.JSONObject obj = new org.json.simple.JSONObject();
			//Map map = new LinkedHashMap();
			LinkedHashMap<String, Object> map = new LinkedHashMap<String, Object>();
				
			map.put("traceReference",traceReference);
			map.put("service",service);
			map.put("type",type);
			map.put("sender",sender);
			map.put("receiver",receiver);
			map.put("document",DataPDU);
			
		
			String jsonText =  obj.toJSONString(map);
			
			

			//String jsonStr = obj.toString();
			logger.debug("jsonStr ::::::::: "+jsonText);
			
			
			jsonText=jsonText.replace("\\/","/");
			logger.debug("After replace fn for forward and backward slash :::::::::::::: "+jsonText);
			
//			jsonText=jsonText.replace("\"","'");
	//		logger.debug("After replace fn for double quotes:::::::::::::: "+jsonText);
			
			//logger.debug("jsonStr :::: "+jsonText.length());
			
			
			/*jsonText = jsonText.substring(0,jsonText.length()-1);
			

			//jsonStr.substring(jsonStr.indexOf("}"), jsonStr.length());
			
			logger.debug("After substr jsonStr ::::::: "+jsonText);
			
			
			jsonText = jsonText+",\"document\""+":"+"\""+DataPDU+"\""+"}";
			
			logger.debug("After adding Document jsonStr :::: "+jsonText);
			
			jsonText=jsonText.replace("\\","");
			
			//String jsonText = createJWTJSON( traceReference, service,  type,  sender,  receiver,  DataPDU);
			
			//jsonText = jsonText.replaceAll("\\", "");
			
			/*org.json.JSONObject jsonObject = XML.toJSONObject(DataPDU);
			
			JSONObject embeddedjson = new JSONObject();
			embeddedjson.put("document",jsonObject.toString());
			
			logger.debug("Generating JWT JSON token..........."+embeddedjson.toString() )
			map.put("document",jsonObject.toString());
			
			String jsonText =  obj.toJSONString(map);*/
			
			
			//return map;
			//jsonText=jsonText.replaceAll("\\", "");
			//logger.debug("After replace ALL ..........."+jsonText ); 

			
			return jsonText;
		
	    }
		public String createJWTJSON(String traceReference,String service, String type, String sender, String receiver, String DataPDU) 
				throws IOException, NoSuchAlgorithmException{
			  
		
			logger.debug("Generating JWT JSON token..........."); 
			 
				  ObjectMapper objectMapper = new ObjectMapper();
				  
				  ObjectNode requestpayload = objectMapper.createObjectNode();
				  requestpayload.put ("traceReference",traceReference);
				  requestpayload.put("service",service );			
				  requestpayload.put("type",type );
				  requestpayload.put("sender",sender );
				  requestpayload.put("receiver",receiver );
				  requestpayload.put("Document",DataPDU);
				  
				  String  token = objectMapper.writeValueAsString(requestpayload);
				  
				  
				  
				  System.out.println("tpken jackson ::: "+token);
				  System.out.println("tpken jackson ::: ");
				  
				  String token1=token.replace("\\\\","");
				  System.out.println("after replace all from  jackson token 1::: "+token1);
				  
				  String token2=token.replace('\\',' ');
				  System.out.println("after replace all from  jackson token 1::: "+token2);
				  
				  
				  return token;
		 }
	    
	    private void getipPort(){    	
	    	logger.debug("In getipPort " );
	    	NCSSAppDatabaseManager dbmanager;					
	    	dbmanager = new NCSSAppDatabaseManager();
	    	dbmanager.connectToDB();
	    	String Query = "select * from RAAST_DIGITAL_PAYMENT_INFO";
	    	try {
	    		        dbmanager.makeConnection();
	    		        logger.debug("getipPort Query is " + Query);
	    				ResultSet rs = dbmanager.executeQuery(Query);

	    				while(rs.next())
	    				{
	    					try {
	    						IP=rs.getString("IP").trim();
	    						PORT=rs.getString("PORT").trim();
	    						USER=rs.getString("Username").trim();
	    						PASSWORD=rs.getString("Password").trim();
	    						URL=rs.getString("URL").trim();	 
	    						CONTENT_TYPE=rs.getString("CONTENT_TYPE").trim();
	    						ACCEPT=rs.getString("ACCEPT").trim();
	    						SENDER_PART_CODE=rs.getString("SENDER_PART_CODE").trim();
	    						SENDER_USER_CODE=rs.getString("SENDER_USER_CODE").trim();
	    						USERNAME=rs.getString("USERNAME").trim();
	    						PASS=rs.getString("PASSWORD").trim();
	    					} catch (SQLException e) {
	    						logger.debug("In getipPort while exception " + e.getMessage() );
	    						e.printStackTrace();
	    					}
	    					logger.debug("RAAST IP is "+ IP +"  =======RAAST PORT is "+ PORT +" ======RAAST USER is "+ USER +" === RAAST URL is "+ URL );
	    				}
	    	} catch (Exception ee) {
	    		logger.debug("getipPort(),Exception is "+ ee.getMessage());
	    		ee.printStackTrace();
	    	}
	    	try {
	    		dbmanager.closeConnection();
	    	} catch (Exception e) {
	    		e.printStackTrace();
	    	}  	
	    	} 		
	    
	    
	    
	    
	   // private  RAASTSession RAASTRemoteInterface = null;
		//private  RAASTHomeSession RAASTHomeInterface = null;
		
		private  DigitalPaymentSession DigitalPaymentRemoteInterface = null;
		private  DigitalPaymentHomeSession DigitalPaymentHomeInterface = null;
		
		private void createRAASTServerConnection() throws Exception {
			logger.debug("Inside createRAASTServerConnection  t3()"); 
		try
		{
		Hashtable ht = new Hashtable(); log(Level.INFO,"1");
		ht.put(Context.INITIAL_CONTEXT_FACTORY,"weblogic.jndi.WLInitialContextFactory"); log(Level.INFO,"2 ");
		logger.debug(""+Context.PROVIDER_URL+ "t3://"+ IP + ":" + PORT);
		ht.put(Context.PROVIDER_URL, "t3://"+ IP + ":" + PORT);//Orion IP		
		//ht.put(Context.PROVIDER_URL, "https://"+ IP + ":" + PORT);//Orion IP 
		logger.debug("3 ");
		InitialContext ctx = new InitialContext(ht); log(Level.INFO,"4 ");
		if (ctx == null) {
			throw new Exception("Initial Context is Null ");
		}
		logger.debug("GOT INITIAL CONTEXT ");	
		DigitalPaymentHomeInterface = (DigitalPaymentHomeSession) ctx.lookup("com/ncss/server/business/DigitalPayment/DigitalPaymentHomeSession");
		logger.debug("after nitial context");	
		if (DigitalPaymentHomeInterface == null) {
			logger.debug("NullPointerException in raastHomeInterface.");
			throw new Exception("RAAST Server Home is Null");
		} else {
			logger.debug(" Home Interface Lookup Successful");
		}
		logger.debug("GETTING REMOTE");
		try {
			DigitalPaymentRemoteInterface = (DigitalPaymentSession) PortableRemoteObject.narrow(DigitalPaymentHomeInterface.create(),DigitalPaymentSession.class);
			if (DigitalPaymentRemoteInterface == null) {
				logger.debug("NullPointerException in Remote.");
				throw new Exception(" Null pointer exception in RAAST Remote ");
			} else {
				logger.debug("raast Remote present");
				logger.debug("***Connection established with RAAST application server***");
			}
		} catch (Exception e) {
			logger.debug("<<< Error in RAAST calls : " + e.getMessage() + " >>>");
			logger.debug(e.getMessage());
			if (e.getMessage() == null) {
				throw new Exception("<<< Error in RAAST calls : Unable to connect to RAAST Server >>>");
			} else {
				throw new Exception("<<< Error in RAAST calls : " + e.getMessage() + " >>>");
			}
		} finally {
			try {
				logger.debug("closing connection");
			} catch (Exception e) {
				logger.debug("exception while cosing connection : " + e);
			}
		}	
		}
		catch(Exception ex)
		{
			logger.debug("exception while cosing connection : " + ex.getMessage());
		}
		}
	
		
				
		   private void getHeaderInfo(){    	
			   logger.debug("In getHeaderInfo " );
		    	NCSSAppDatabaseManager dbmanager;					
		    	dbmanager = new NCSSAppDatabaseManager();
		    	dbmanager.connectToDB();
		    	String Query = "select * from RAAST_DIGITAL_PAYMENT_INFO";
		    	try {
		    		        dbmanager.makeConnection();
		    		        logger.debug("getHeaderInfo Query is " + Query);
		    				ResultSet rs = dbmanager.executeQuery(Query);

		    				while(rs.next())
		    				{
		    					try {
		    						  CONTENT_TYPE=rs.getString("CONTENT_TYPE").trim();
		    						  ACCEPT=rs.getString("ACCEPT").trim();
		    						  SENDER_PART_CODE=rs.getString("SENDER_PART_CODE").trim();
		    						  SENDER_USER_CODE=rs.getString("SENDER_USER_CODE").trim();
		    						  USERNAME=rs.getString("USERNAME").trim();
		    						  PASS=rs.getString("PASSWORD").trim();
		    										
		    					} catch (SQLException e) {
		    						logger.debug("In getHeaderInfo while exception " + e.getMessage() );
		    						e.printStackTrace();
		    					}
		    					  //log(Level.INFO, "RAAST Header is "+ header +"  =======RAAST keys is "+ keys  );
		    				}
		    	} catch (Exception ee) {
		    		logger.debug("getHeaderInfo(),Exception is "+ ee.getMessage());
		    		ee.printStackTrace();
		    	}
		    	try {
		    		dbmanager.closeConnection();
		    	} catch (Exception e) {
		    		e.printStackTrace();
		    	}  	
		    	} 		
		   
				public String getSystemDate() throws SQLException
		    {
					logger.debug("In function getSystemDate() " );
				NCSSAppDatabaseManager ncssDBM;					
				ncssDBM = new NCSSAppDatabaseManager();
		    	ncssDBM.connectToDB();
		    	try {
					ncssDBM.makeConnection();
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
	  			ResultSet rs = null;
	  			String sysDate = "";
	  	
	  			String sysDtaeQuery = "Select to_char(SYSTEM_DATE,'YYYY-MM-DD') tdate FROM SYSTEM ";
	  			logger.debug("sysDtaeQuery is " +sysDtaeQuery);
            	   	rs=ncssDBM.executeQuery(sysDtaeQuery);  
            	   	
            	   	while (rs != null && rs.next()) {
            	   		sysDate=rs.getString("tdate");
            	   		logger.debug( "SYSTEM_DATE is  " +sysDate);
            	   	}
            		
            	   	return sysDate;
			} 
			
				
				public static String createJWTAndSign(String iss, String iat, String exp, String asrvType, String certIss, String certSN)
					throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, KeyStoreException, UnrecoverableKeyException {

		 System.out.println("Generating JWT snd Signing with Private Key..........."); 
		 
		 File is = new File("/ncsswblj/java6_64/bin/raastcertfinal.jks");
		 PrivateKey  priKey = loadKeyStore(is,"storepassraastfinal", "JKS");
		 String keypem  = "-----BEGIN PRIVATE KEY-----\n" + DatatypeConverter.printBase64Binary(priKey.getEncoded()) + "\n-----END PRIVATE KEY-----\n";
    System.out.println("keypem is new "+keypem);
    
  	SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;
  	LinkedHashMap<String, Object> headers = new LinkedHashMap<String, Object>();
			  headers.put("alg", "RS256");
			  headers.put("typ", "JWT");
			  headers.put("x5t", "HWpFGLg4wZ47Gj7hgc5yahzJl5c");
			
   		  System.out.println("headers LinkedHashMap  "+headers);
			 
			  JwtBuilder builder = Jwts.builder().setHeaderParams(headers).claim("iss", iss)
			          .claim("iat", iat).claim("exp", exp).claim("asrv_type",asrvType).claim("asrv_cert_iss",certIss).claim("asrv_cert_sn",certSN)
			           .signWith(signatureAlgorithm, getFinalPrivateKey(keypem));
			  
			  String token = builder.compact();
			  
			  System.out.println("token is "+token);
			  return token;
	 }
				
				
	
	 public static PrivateKey loadKeyStore(final File keystoreFile,
			    final String password, final String keyStoreType)
			    throws KeyStoreException, IOException, NoSuchAlgorithmException,
			    CertificateException, UnrecoverableKeyException {
			  if (keystoreFile == null) {
			    throw new IllegalArgumentException("Keystore url may not be null");
			  }
		 
			  PrivateKey key = null;
			  System.out.println("Initializing key store: {}"+ keystoreFile.getAbsolutePath());
			  final URI keystoreUri = keystoreFile.toURI();
			  final URL keystoreUrl = keystoreUri.toURL();
			  final KeyStore keystore = KeyStore.getInstance(keyStoreType);
			  InputStream is = null;
			  try {
			    is = keystoreUrl.openStream();
			    keystore.load(is, null == password ? null : password.toCharArray());
			    System.out.println("Loaded key store");
			    key = (PrivateKey)keystore.getKey("aliasraastfinal", "keypassraastfinal".toCharArray());
			    System.out.println("Loaded key store 1");
		    
		        /* Get certificate of public key */
			    java.security.cert.Certificate cert = keystore.getCertificate("aliasraastfinal"); 
		        //Certificate certificate = ks.getCertificate(stsAlias);
		       // Key key = keystore.getKey("aliasraastfinal", "storepassraastfinal".toCharArray());
		        
		        /* Here it prints the public key*/
		        System.out.println("\nPrivate Key:");
		        System.out.println(key);
			    
		        
		        
			  } finally {
				  if (is !=  null  ) {
				      is.close();
				    }
				 }
			  return key;
			}
	 
	 
	
	 private static PrivateKey getFinalPrivateKey(String pemStr) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		  System.out.println("get private key fn");
		  PrivateKey privKey = null;
	
		  String privateKeyPem = pemStr.replace("-----BEGIN PRIVATE KEY-----", "").replaceAll("\\n", "").replace("-----END PRIVATE KEY-----", "");
		  
		  byte[] keyContentAsBytesPri =  Base64.decodeBase64(privateKeyPem.getBytes());

			 try {
			   KeyFactory fact1 = KeyFactory.getInstance("RSA");
			   System.out.println("5");
			   PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(keyContentAsBytesPri);
			   System.out.println("6");
			   PrivateKey privKey1 = fact1.generatePrivate(priKeySpec);
			   System.out.println("7");
			   System.out.println(privKey1);
			   System.out.println("8");
			   privKey = privKey1;
			 }catch (Throwable t) {
			   t.printStackTrace();
			 }
		 return privKey;
		 }
	
	
		private String getRAAST_PAYMENT_TRACE_REF() 
	    {
			NCSSAppDatabaseManager dbmanager;
			dbmanager = new NCSSAppDatabaseManager();
			dbmanager.connectToDB();
			String raastPaymentTraceRef="";
			String Query = "SELECT 'NCCP'||''||KYCLIVE.RAAST_PAYMENT_TRACE_REF.NEXTVAL TRACE_REFERENCE FROM DUAL ";
			try {
				dbmanager.makeConnection();

				ResultSet rs = dbmanager.executeQuery(Query);

				while (rs.next()) {
					try {

						raastPaymentTraceRef= rs.getString("TRACE_REFERENCE").trim();
		
					} catch (SQLException e) {

						e.printStackTrace();
					}
					System.out.println("raastPaymentTraceRef is " + raastPaymentTraceRef);
				}
			} catch (Exception ee) {

				ee.printStackTrace();
			}
			try {
				dbmanager.closeConnection();
			} catch (Exception e) {
				e.printStackTrace();
			}

			return raastPaymentTraceRef;
		}
}
