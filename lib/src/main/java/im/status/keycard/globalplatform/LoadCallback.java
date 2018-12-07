package im.status.keycard.globalplatform;

/**
 * Callback interface using during package loading process.
 */
public interface LoadCallback {
  /**
   * Called when a block is loaded.
   *
   * @param loadedBlock The number of the loaded block (1 based)
   * @param blockCount the total number of blocks.
   */
  void blockLoaded(int loadedBlock, int blockCount);
}
