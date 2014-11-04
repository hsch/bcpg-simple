package trbl.io.gnupg;

import java.io.File;
import java.io.IOException;
import java.util.List;

public class Processes {

  public static Process executeInternal(final File workingDirectory, final List<String> command) throws IOException {
    final ProcessBuilder processBuilder = new ProcessBuilder(command);
    processBuilder.directory(workingDirectory);
    System.out.println(processBuilder.command());
    return processBuilder.start();
  }

}
