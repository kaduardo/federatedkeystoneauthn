package connection;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.apache.http.HttpEntity;

public class OurUtil {
	/**
	 * Converts a HttpEntity to String format
	 * @param ent
	 * @return
	 */
	public static String httpEntityToString(HttpEntity ent) {
		try {
			InputStream in = ent.getContent();
			InputStreamReader reader = new InputStreamReader(in);
			BufferedReader bfReader = new BufferedReader(reader);
			String s, content;
			StringBuilder contentBuilder = new StringBuilder();
			while ((s = bfReader.readLine()) != null) {
				contentBuilder.append(s);
			}
			content = contentBuilder.toString();
//			System.out.println("Entity content" + content);
			return content;
		} catch (IOException ex) {
			System.out.println("Error while checking keystone authentication response");
			return null;
		}
		catch (Exception e) {
			e.printStackTrace();
			return null;
	    }
	}
}
