package trbl.io.gnupg;

class ProcessException extends Exception {

  private static final long serialVersionUID = 1L;

  private final int exitCode;

  ProcessException(final String message, final int exitCode) {
    super(message);
    this.exitCode = exitCode;
  }

  ProcessException(final String message, final Throwable cause) {
    super(message, cause);
    this.exitCode = -1;
  }

  public int getExitCode() {
    return exitCode;
  }

}
