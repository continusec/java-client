/*
   Copyright 2016 Continusec Pty Ltd

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package com.continusec.client;

import java.util.ArrayList;
import java.util.List;
import java.net.URL;
import java.net.HttpURLConnection;
import java.io.OutputStream;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonArray;

import org.apache.commons.io.IOUtils;

/**
 * Main entry point for interacting with Continusec's Verifiable Data Structure APIs.
 * <pre>{@code
 * ContinusecClient client = new ContinusecClient("your account number", "your secret key");
 * VerifiableLog log = client.getVerifiableLog("testlog");
 * // use the log ...
 *
 * VerifiableMap map = client.getVerifiableMap("testmap");
 * // use the map ...
 *
 * }</pre>
 */
public class ContinusecClient {
	/**
	 * HEAD can be substituted for tree size in requests for fetch tree hashes. Specifying
	 * this values means to fetch the latest tree hash present.
	 */
	public static final int HEAD = 0;

	private String account;
	private String apiKey;
	private String baseURL;

	/**
	 * Create an anonymous ContinusecClient for a given account. The account must have
	 * at least one API Access rule configured to allow public ("*") access.
	 *
	 * @param account the account number, found on the "Settings" tab in the console.
	 */
	public ContinusecClient(String account) {
		this(account, null);
	}

	/**
	 * Create a ContinusecClient for a given account with specified API Key.
	 *
	 * @param account the account number, found on the "Settings" tab in the console.
	 * @param apiKey the API Key, found on the "API Keys" tab in the console.
	 */
	public ContinusecClient(String account, String apiKey) {
		this(account, apiKey, "https://api.continusec.com");
	}

	/**
	 * Create a ContinusecClient for a given account with specified API Key and custom
	 * base URL. This is normally only used for unit tests of the ContinusecClient API.
	 *
	 * @param account the account number, found on the "Settings" tab in the console.
	 * @param apiKey the API Key, found on the "API Keys" tab in the console.
	 * @param baseURL the base URL to send API requests to.
	 */
	public ContinusecClient(String account, String apiKey, String baseURL) {
		this.account = account;
		this.apiKey = apiKey;
		this.baseURL = baseURL;
	}

	/**
	 * Return a pointer to a verifiable map that belongs to this account.
	 *
	 * @param name name of the map to access.
	 * @return an object that allows manipulation of the specified map.
	 */
	public VerifiableMap getVerifiableMap(String name) {
		return new VerifiableMap(this, "/map/" + name);
	}

	/**
	 * Return a pointer to a verifiable log that belongs to this account.
	 *
	 * @param name name of the log to access.
	 * @return an object that allows manipulation of the specified log.
	 */
	public VerifiableLog getVerifiableLog(String name) {
		return new VerifiableLog(this, "/log/" + name);
	}

	/**
	 * Fetch the list of logs held by this account.
	 * @return list of logs
	 * @throws ContinusecException upon error
	 */
	public List<LogInfo> listLogs() throws ContinusecException {
		ResponseData rd = this.makeRequest("GET", "/logs", null, null);
		try {
			JsonObject o = new JsonParser().parse(new String(rd.data, "UTF-8")).getAsJsonObject();
			ArrayList<LogInfo> rv = new ArrayList<LogInfo>();
			for (JsonElement e : o.getAsJsonArray("results")) {
				rv.add(new LogInfo(e.getAsJsonObject().getAsJsonPrimitive("name").getAsString()));
			}
			return rv;
		} catch (UnsupportedEncodingException e) {
			throw new ContinusecException(e);
		}
	}

	/**
	 * Fetch the list of maps held by this account.
	 * @return list of maps
	 * @throws ContinusecException upon error
	 */
	public List<MapInfo> listMaps() throws ContinusecException {
		ResponseData rd = this.makeRequest("GET", "/maps", null, null);
		try {
			JsonObject o = new JsonParser().parse(new String(rd.data, "UTF-8")).getAsJsonObject();
			ArrayList<MapInfo> rv = new ArrayList<MapInfo>();
			for (JsonElement e : o.getAsJsonArray("results")) {
				rv.add(new MapInfo(e.getAsJsonObject().getAsJsonPrimitive("name").getAsString()));
			}
			return rv;
		} catch (UnsupportedEncodingException e) {
			throw new ContinusecException(e);
		}
	}

	/**
	 * Package private common method for making underlying HTTP requests to API server.
	 * @param method the HTTP method to use.
	 * @param path the path underneath this account to use.
	 * @param data for PUT and POST methods, the data (if any to) to send in body.
	 * @param extraHeaders additional headers to include in the request
	 * @return the body and headers.
	 * @throws ContinusecException for any network errors, or non 200 responses.
	 */
	protected ResponseData makeRequest(String method, String path, byte[] data, String[][] extraHeaders) throws ContinusecException {
		try {
			URL url = new URL(this.baseURL + "/v1/account/" + this.account + path);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();

			conn.setRequestMethod(method);
			if (this.apiKey != null) {
				conn.setRequestProperty("Authorization", "Key " + this.apiKey);
			}
			if (extraHeaders != null) {
				for (int i = 0; i < extraHeaders.length; i++) {
					conn.setRequestProperty(extraHeaders[i][0], extraHeaders[i][1]);
				}
			}
			if (method.equals("POST") || method.equals("PUT")) {
				conn.setDoOutput(true);
				OutputStream out = conn.getOutputStream();
				if (data != null && data.length > 0) {
					out.write(data);
				}
				out.flush();
				out.close();
			}

			conn.connect();
			int code = conn.getResponseCode();
			switch (code) {
			case 200:
				return new ResponseData(IOUtils.toByteArray(conn.getInputStream()), conn.getHeaderFields());
			case 400:
				throw new InvalidRangeException();
			case 403:
				throw new UnauthorizedAccessException();
			case 404:
				throw new ObjectNotFoundException();
			case 409:
				throw new ObjectConflictException();
			default:
				throw new InternalErrorException();
			}
		} catch (MalformedURLException e) {
			throw new ContinusecNetworkException(e);
		} catch (IOException e) {
			throw new ContinusecNetworkException(e);
		}
	}
}
