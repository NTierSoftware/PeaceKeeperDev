package org.peacekeeper.rest;// Created by John Donaldson, NTier Software Engineering on 4/3/2016.


import com.android.volley.Request.Method;
import com.android.volley.Response.ErrorListener;
import com.android.volley.Response.Listener;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.StringRequest;


import org.peacekeeper.util.pkUtility;

public class Get {
private static final org.slf4j.Logger mLog	= org.slf4j.LoggerFactory.getLogger(Get.class);

public static enum URLGet { Test, Status; }//enum GET
String url = "https://localhost:8181//GaelWebSvcGF4//rest//GAEL//Status";

//http://developer.android.com/training/volley/requestqueue.html
/*StringRequest stringRequest = new StringRequest(Method.GET, url,
                       new Listener<String>() {
                           @Override
                           public void onResponse(String response) {
                               mLog.debug("RESPONSE!!:\t"+ response);
                           }
                       },
                       new ErrorListener() {
                           @Override
                           public void onErrorResponse(VolleyError error) {
                               // Handle error
                           }
                       });*/

public Get(String url){

	//http://developer.android.com/training/volley/requestqueue.html
	StringRequest stringRequest = new StringRequest(Method.GET, url,
                                   new Listener<String>() {
                                       @Override
                                       public void onResponse(String response) {
                                           mLog.debug("RESPONSE!!:\t"+ response);
                                       }
                                   },
                                   new ErrorListener() {
                                       @Override
                                       public void onErrorResponse(VolleyError error) {
	                                       mLog.debug("RESPONSE!!:\n");
	                                       mLog.debug(error.getLocalizedMessage() );
                                       }
                                   });

	pkUtility.getInstance().getRequestQueue().add(stringRequest);
}
}//class Get
