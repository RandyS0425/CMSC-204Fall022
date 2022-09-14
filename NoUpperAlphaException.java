/**
 * @author Randy Barreda
 *
 */
@SuppressWarnings("serial")
public class NoUpperAlphaException extends Exception {
	public NoUpperAlphaException() {
		super("The password must contain at least one uppercase alphabetic character");
	}
}