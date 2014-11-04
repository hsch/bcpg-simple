package trbl.io.gnupg;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;

public class GnuPGAgent {

  private final File directory;
  private final Runnable closeAction;

  public static GnuPGAgent newInstance() throws IOException {
    final File directory = Files.createTempDirectory("gnupg-agent-").toFile();
    final Process process = Processes.executeInternal(directory,
        Arrays.asList("gpg-agent", "--daemon", "--use-standard-socket", "--home", directory.getAbsolutePath()));
    return new GnuPGAgent(directory, new ProcessDestroy(process));
  }

  private GnuPGAgent(final File directory, final Runnable closeAction) {
    this.directory = directory;
    this.closeAction = closeAction;
  }

  public GnuPG newGnuPG() {
    return new GnuPG(directory);
  }

  public void close() throws IOException {
    closeAction.run();
  }

}
