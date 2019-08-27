package eu.roebert.crypto.exceptions;

public class ECDSAException extends Exception {
	private static final long serialVersionUID = 8439057567799405539L;

	public ECDSAException()
	{
		super("An unexpected error occurred in the ECDSA routine.");
	}

	public ECDSAException(String message)
	{
		super(message);
	}
}
