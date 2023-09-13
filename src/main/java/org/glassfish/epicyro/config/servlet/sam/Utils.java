/*
 * Copyright (c) 2015, 2020 Oracle and/or its affiliates. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 */

package org.glassfish.epicyro.config.servlet.sam;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.regex.Pattern.quote;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * An assortment of various utility methods.
 *
 * @author Arjan Tijms
 *
 */
public final class Utils {

	private static final String ERROR_UNSUPPORTED_ENCODING = "UTF-8 is apparently not supported on this platform.";

    private Utils() {}

	public static boolean notNull(Object... objects) {
		for (Object object : objects) {
			if (object == null) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Returns true if the given string is null or is empty.
	 *
	 * @param string The string to be checked on emptiness.
	 * @return True if the given string is null or is empty.
	 */
	public static boolean isEmpty(String string) {
		return string == null || string.isEmpty();
	}

	/**
	 * Returns <code>true</code> if the given array is null or is empty.
	 *
	 * @param array The array to be checked on emptiness.
	 * @return <code>true</code> if the given array is null or is empty.
	 */
	public static boolean isEmpty(Object[] array) {
		return array == null || array.length == 0;
	}

	/**
	 * Returns <code>true</code> if the given collection is null or is empty.
	 *
	 * @param collection The collection to be checked on emptiness.
	 * @return <code>true</code> if the given collection is null or is empty.
	 */
	public static boolean isEmpty(Collection<?> collection) {
		return collection == null || collection.isEmpty();
	}

	/**
	 * Returns <code>true</code> if the given object equals one of the given objects.
	 * @param <T> The generic object type.
	 * @param object The object to be checked if it equals one of the given objects.
	 * @param objects The argument list of objects to be tested for equality.
	 * @return <code>true</code> if the given object equals one of the given objects.
	 */
	@SafeVarargs
	public static <T> boolean isOneOf(T object, T... objects) {
		for (Object other : objects) {
			if (object == null ? other == null : object.equals(other)) {
				return true;
			}
		}

		return false;
	}

	public static String getBaseURL(HttpServletRequest request) {
		String url = request.getRequestURL().toString();
		return url.substring(0, url.length() - request.getRequestURI().length()) + request.getContextPath();
	}

	public static void redirect(HttpServletResponse response, String location) {
		try {
			response.sendRedirect(location);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	public static void redirect(HttpServletRequest request, HttpServletResponse response, String location) {
		try {
			if (isFacesAjaxRequest(request)) {
				response.setHeader("Cache-Control", "no-cache,no-store,must-revalidate");
				response.setDateHeader("Expires", 0);
				response.setHeader("Pragma", "no-cache"); // Backwards compatibility for HTTP 1.0.
				response.setContentType("text/xml");
				response.setCharacterEncoding(UTF_8.name());
				response.getWriter().printf(FACES_AJAX_REDIRECT_XML, location);
			}
			else {
				response.sendRedirect(location);
			}
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	private static final Set<String> FACES_AJAX_HEADERS = unmodifiableSet("partial/ajax", "partial/process");
	private static final String FACES_AJAX_REDIRECT_XML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
		+ "<partial-response><redirect url=\"%s\"></redirect></partial-response>";

	public static boolean isFacesAjaxRequest(HttpServletRequest request) {
		return FACES_AJAX_HEADERS.contains(request.getHeader("Faces-Request"));
	}

	@SuppressWarnings("unchecked")
	public static <E> Set<E> unmodifiableSet(Object... values) {
		Set<E> set = new HashSet<>();

		for (Object value : values) {
			if (value instanceof Object[]) {
				for (Object item : (Object[]) value) {
					set.add((E) item);
				}
			}
			else if (value instanceof Collection<?>) {
				for (Object item : (Collection<?>) value) {
					set.add((E) item);
				}
			}
			else {
				set.add((E) value);
			}
		}

		return Collections.unmodifiableSet(set);
	}

	public static String encodeURL(String string) {
		if (string == null) {
			return null;
		}

		try {
			return URLEncoder.encode(string, UTF_8.name());
		}
		catch (UnsupportedEncodingException e) {
			throw new UnsupportedOperationException(ERROR_UNSUPPORTED_ENCODING, e);
		}
	}

	public static String decodeURL(String string) {
		if (string == null) {
			return null;
		}

		try {
			return URLDecoder.decode(string, UTF_8.name());
		}
		catch (UnsupportedEncodingException e) {
			throw new UnsupportedOperationException(ERROR_UNSUPPORTED_ENCODING, e);
		}
	}

	/**
	 * Converts the given request query string to request parameter values map.
	 * @param queryString The request query string.
	 * @return The request query string as request parameter values map.
	 */
	public static Map<String, List<String>> toParameterMap(String queryString) {
		String[] parameters = queryString.split(quote("&"));
		Map<String, List<String>> parameterMap = new LinkedHashMap<>(parameters.length);

		for (String parameter : parameters) {
			if (parameter.contains("=")) {
				String[] pair = parameter.split(quote("="));
				String key = decodeURL(pair[0]);
				String value = (pair.length > 1 && !isEmpty(pair[1])) ? decodeURL(pair[1]) : "";
				List<String> values = parameterMap.computeIfAbsent(key, k -> new ArrayList<>(1));

				values.add(value);
			}
		}

		return parameterMap;
	}

	/**
	 * Converts the given request parameter values map to request query string.
	 * @param parameterMap The request parameter values map.
	 * @return The request parameter values map as request query string.
	 */
	public static String toQueryString(Map<String, List<String>> parameterMap) {
		StringBuilder queryString = new StringBuilder();

		for (Entry<String, List<String>> entry : parameterMap.entrySet()) {
			String name = encodeURL(entry.getKey());

			for (String value : entry.getValue()) {
				if (queryString.length() > 0) {
					queryString.append("&");
				}

				queryString.append(name).append("=").append(encodeURL(value));
			}
		}

		return queryString.toString();
	}

	public static String getSingleParameterFromQueryString(String queryString, String paramName) {
		if (!isEmpty(queryString)) {
			Map<String, List<String>> requestParameters = toParameterMap(queryString);

			if (!isEmpty(requestParameters.get(paramName))) {
				return requestParameters.get(paramName).get(0);
			}
		}

		return null;
	}

	public static long stream(InputStream input, OutputStream output) throws IOException {
		try (ReadableByteChannel inputChannel = Channels.newChannel(input);
			WritableByteChannel outputChannel = Channels.newChannel(output))
		{
			ByteBuffer buffer = ByteBuffer.allocateDirect(10240);
			long size = 0;

			while (inputChannel.read(buffer) != -1) {
				buffer.flip();
				size += outputChannel.write(buffer);
				buffer.clear();
			}

			return size;
		}
	}

	/**
	 * Read the given input stream into a byte array. The given input stream will implicitly be closed after streaming,
	 * regardless of whether an exception is been thrown or not.
	 * @param input The input stream.
	 * @return The input stream as a byte array.
	 * @throws IOException When an I/O error occurs.
	 */
	public static byte[] toByteArray(InputStream input) throws IOException {
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		stream(input, output);
		return output.toByteArray();
	}

   public static boolean isImplementationOf(Method implementationMethod, Method interfaceMethod) {
        return
            interfaceMethod.getDeclaringClass().isAssignableFrom(implementationMethod.getDeclaringClass()) &&
            interfaceMethod.getName().equals(implementationMethod.getName()) &&
            Arrays.equals(interfaceMethod.getParameterTypes(), implementationMethod.getParameterTypes());
    }

   public static Method getMethod(Class<?> base, String name, Class<?>... parameterTypes) {
        try {
            // Method literals in Java would be nice
            return base.getMethod(name, parameterTypes);
        } catch (NoSuchMethodException | SecurityException e) {
            throw new IllegalStateException(e);
        }
    }

}
