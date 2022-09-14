
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * @author Randy Barreda
 *
 */
public class PasswordCheckerUtility {

	/**
	 * Compare equality of two passwords
	 * @param password  string to be checked for
	 * @param passwordConfirm  string to be checked against password for
	 * @throws UnmatchedException thrown if not same (case sensitive)
	 */ 
	public static void comparePasswords(String password,String passwordConfirm) throws UnmatchedException
     {
		if(!password.equals(passwordConfirm)) 
			throw new  UnmatchedException();
		
     }
	
	/**
	 * Compare equality of two passwords
	 * @param password string to be checked for
	 * @param passwordConfirm string to be checked against password for
	 * @return true if both same (case sensitive)
	 */
	public static boolean comparePasswordsWithReturn(String password,String passwordConfirm) 
	{
		if(password.equals(passwordConfirm))
			return true;
		return false;
	}
	
	/**
	 * Reads a file of passwords and the passwords that failed the check will be added to an invalidPasswords with the reason
	 * @param passwords list of passwords read from a file
	 * @return  invalidPasswords - ArrayList of invalid passwords in the correct format
	 */
	public static ArrayList<String> getInvalidPasswords(ArrayList<String> passwords) {
		
	ArrayList<String> Invalid_password = new ArrayList<String>();
		
	for(int i=0; i<passwords.size(); i++) {
	
		try {
			if (!isValidPassword(passwords.get(i)))
				Invalid_password.add(passwords.get(i));
		} catch (LengthException | NoUpperAlphaException | NoLowerAlphaException | NoDigitException
				| NoSpecialCharacterException | InvalidSequenceException e) {
			Invalid_password.add(passwords.get(i) + " -> " + e.getMessage());
		}
		
		
	}
	
	return Invalid_password;
	
	}
	
	/**
	 * Weak password length check - Password contains 6 to 9 characters , still considers valid, just weak
	 * @param password string to be checked for Sequence requirement
	 * @return true if password contains 6 to 9 characters
	 */
	public static boolean hasBetweenSixAndNineChars(String password) {
		if(password.length()>=6  && password.length()<=9 ) 
			return true;
		
		return false;
	}
	
	/**
	 * Checks the password Digit requirement - Password must contain a numeric character
	 * @param password string to be checked for Digit requirement
	 * @return true if meet Digit requirement
	 * @throws NoDigitException thrown if does not meet Digit requirement
	 */
	public static boolean hasDigit(String password)throws NoDigitException{
		int count=0;
		for (int i=0; i<password.length(); i++) {
			if(Character.isDigit(password.charAt(i)))
				count++;
			
		}
		if(count<=0) 
			throw new NoDigitException();
		else	
 
			return true;
	
		
	}
	
	/**
	 * Checks the password lowercase requirement - Password must contain a lowercase alpha character
	 * @param password string to be checked for lowercase requirement
	 * @return true if meet lowercase requirement
	 * @throws NoLowerAlphaException thrown if does not meet lowercase requirement
	 */
	public static boolean hasLowerAlpha(String password)throws NoLowerAlphaException{
		int count=0;
		for (int i=0; i<password.length(); i++) {
			
			if(Character.isLowerCase(password.charAt(i)))
				count++;
			
		}
		if(count>0) 
			
			return true;
		else	
			throw new NoLowerAlphaException();
	}
	
	/**
	 * Checks the password Sequence requirement - Password should not contain more than 2 of the same character in sequence
	 * @param password string to be checked for Sequence requirement
	 * @return false if does NOT meet Sequence requirement
	 * @throws InvalidSequenceException thrown if does not meet Sequence requirement
	 */
	public static boolean hasSameCharInSequence(String password) throws InvalidSequenceException{
		int count=0;
		for(int i=0; i<password.length()-1;i++) {
			if(password.charAt(i) == password.charAt(i+1) &&  count<2 ) {
				count++;
			}
			else if(password.charAt(i) != password.charAt(i+1) &&  count<2 ) {
				count=0;
			}
				
		}
		if(count>=2)
			throw new InvalidSequenceException();
		
		return true;
		
	}
	
	/**
	 * Checks the password SpecialCharacter requirement - Password must contain a Special Character
	 * @param password string to be checked for SpecialCharacter requirement
	 * @return true if meet SpecialCharacter requirement
	 * @throws NoSpecialCharacterException
	 */
	public static boolean hasSpecialChar(String password) throws NoSpecialCharacterException {
		Pattern pattern = Pattern.compile("[a-zA-Z0-9]*");
		Matcher matcher = pattern.matcher(password);
		if (matcher.matches())
			throw new NoSpecialCharacterException();
		else
			return true;
			
	}
	
	/**
	 * Checks the password alpha character requirement - Password must contain an uppercase alpha characte
	 * @param password string to be checked for alpha character requirement
	 * @return true if meet alpha character requirement
	 * @throws NoUpperAlphaException thrown if does not meet alpha character requirement
	 */
	public static boolean hasUpperAlpha(String password)throws NoUpperAlphaException {
		int count=0;
		for (int i=0; i<password.length(); i++) {
			if(Character.isUpperCase(password.charAt(i)))
				count++;
		}
		if(count<=0) 
			throw new NoUpperAlphaException();	
		else 
			return true;
	}
	
	/**
	 * Checks the password length requirement - � The password must be at least 6 characters long
	 * @param password string to be checked for length
	 * @return true if meet min length requirement
	 * @throws LengthException thrown if does not meet min length requirement
	 */
	public static boolean isValidLength(String password)throws LengthException {
		if(password.length()<6)
			throw new LengthException();
		else 
			return true;
	}
	/**
	 * Return true if valid password (follows all rules from above), returns false if an invalid password
	 * @param password string to be checked for validity
	 * @return true if valid password (follows all rules from above), false if an invalid password
	 * @throws LengthException - thrown if length is less than 6 characters
	 * @throws NoUpperAlphaException- thrown if no uppercase alphabetic
	 * @throws NoLowerAlphaException- thrown if no lowercase alphabetic
	 * @throws NoDigitException- thrown if no digit
	 * @throws NoSpecialCharacterException - thrown if does not meet SpecialCharacter requirement
	 * @throws InvalidSequenceException - thrown if more than 2 of same character.
	 */
	public static boolean isValidPassword(String password)
            throws LengthException,
                   NoUpperAlphaException,
                   NoLowerAlphaException,
                   NoDigitException,
                   NoSpecialCharacterException,
                   InvalidSequenceException{
		return isValidLength(password) 
				&& hasDigit(password) 
				&& hasUpperAlpha(password) 
				&& hasLowerAlpha(password) 
				&& hasSpecialChar(password) 
				&& hasSameCharInSequence(password);
		
	}
	/**
	 * Checks if password is valid but between 6 -9 characters
	 * @param password string to be checked if weak password
	 * @return true if length of password is between 6 and 9 (inclusive).
	 * @throws WeakPasswordException
	 */
	public static boolean isWeakPassword(String password)throws WeakPasswordException {
		if(password.length()<10)
			throw new WeakPasswordException();
			
		else 
			return false;
	}
}