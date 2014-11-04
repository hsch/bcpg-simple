package trbl.io.gnupg;

class ProcessDestroy implements Runnable {

  private final Process process;

  public ProcessDestroy(final Process process) {
    this.process = process;
  }

  public void run() {
    process.destroy();
  }

}
