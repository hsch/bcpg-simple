package trbl.io.gnupg;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class GnuPG {

  private final File directory;

  GnuPG(final File directory) {
    this.directory = directory;
  }

  public File newTempFile() throws IOException {
    return File.createTempFile("gnupg-", ".tmp", directory);
  }

  public String help() throws ProcessException {
    return execute("--help");
  }

  public String importKey(final File keyFile) throws ProcessException {
    return execute("--import", keyFile.getAbsolutePath());
  }

  public String listKeys() throws ProcessException {
    return execute("--list-keys");
  }

  public String listSecretKeys() throws ProcessException {
    return execute("--list-secret-keys");
  }

  public String decrypt(final File encryptedFile, final char[] passphrase) throws ProcessException {
    return execute("--batch", "--passphrase", new String(passphrase), "--decrypt", encryptedFile.getAbsolutePath());
  }

  public String encrypt(final String recipient, final File file, final File encryptedDataFile, final char[] passphrase) throws ProcessException {
    return execute("-r", recipient, "--batch", "--yes", "--trust-model", "always", "--passphrase", new String(passphrase), "-o",
        encryptedDataFile.getAbsolutePath(), "--armor", "--sign", "--encrypt", file.getAbsolutePath());
  }

  public String generateKeys(final String id, final char[] passphrase) throws IOException, ProcessException {
    final File script = newTempFile();
    final PrintWriter printWriter = new PrintWriter(new FileOutputStream(script));
    try {
      printWriter.println("Key-Type: default");
      printWriter.println("Subkey-Type: default");
      printWriter.println("Name-Real: " + id);
      printWriter.println("Expire-Date: 0");
      printWriter.println("Passphrase: " + new String(passphrase));
    }
    finally {
      printWriter.close();
    }
    return execute("--batch", "--gen-key", script.getAbsolutePath());
  }

  public String export(final String id) throws ProcessException {
    return execute("--export", "--armor", id);
  }

  public String fingerprint() throws ProcessException {
    return execute("--fingerprint");
  }

  private String execute(final String... arguments) throws ProcessException {
    final List<String> command = new ArrayList<String>();
    command.add("gpg");
    command.add("--home");
    command.add(directory.getAbsolutePath());
    command.addAll(Arrays.asList(arguments));
    final Process process;
    try {
      process = Processes.executeInternal(directory, command);
    }
    catch (final IOException e) {
      throw new ProcessException("Failed to start process", e);
    }
    final StringBuilder processOutput = new StringBuilder();
    try {
      {
        final BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        try {
          String line;
          while ((line = reader.readLine()) != null) {
            processOutput.append(line).append("\n");
          }
        }
        finally {
          reader.close();
        }
      }
      {
        final BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
        try {
          String line;
          while ((line = reader.readLine()) != null) {
            System.err.println(line);
          }
        }
        finally {
          reader.close();
        }
      }
    }
    catch (final IOException e) {
      throw new ProcessException("Data unavailable", e);
    }
    final int exitCode;
    try {
      exitCode = process.waitFor();
    }
    catch (final InterruptedException e) {
      throw new ProcessException("Interrupted before process", e);
    }
    if (0 != exitCode) {
      throw new ProcessException("Unexpected exit code: " + exitCode, exitCode);
    }
    System.out.println(processOutput);
    return processOutput.toString();
  }
}
