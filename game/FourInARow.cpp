#include <iostream>
#include <stdexcept>
#include <limits>
#include "./FourInARow.h"
#include "../utils/shared-constants.h"
using namespace std;
// ---------------------------------------
// 				UTILITY
// ---------------------------------------

void clearStdin() {
    cin.clear();
    cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

// ---------------------------------------

// ---------------------------------------
// 	   CLASS FUNCTIONS IMPLEMENTATION
// ---------------------------------------

FourInARow::FourInARow(string opponent)
    : matchFinished(false),
      result(Result::LOSS),
      turn(0),
      board(ROWS, vector<int>(COLUMNS, EMPTY_SPACE)),
      opponent(std::move(opponent)){}

bool FourInARow::isValidMove(const uint8_t &columnIndex){

    if(!matchFinished && (columnIndex < COLUMNS) && (board[ROWS - 1][columnIndex] == EMPTY_SPACE)){

        return true;
    
    }

    if(!matchFinished)
            cout << "!matchFinished\n\n";
        
    if(columnIndex < COLUMNS)
            cout << "columnIndex < COLUMNS\n\n";
    
    if(board[ROWS - 1][columnIndex] == EMPTY_SPACE)
            cout << "board[ROWS - 1][columnIndex] == EMPTY_SPACE\n\n";
    
    return false;
}

bool FourInARow::registerMove(const uint8_t columnIndex, bool opponentMove) {
    if (!isValidMove(columnIndex)){
        cout << "Move not valid\n";
        return false;
    }

    turn++;

    /*
     * Find the first available empty space in the column (bottom-up view).
     * The above check ensures that there is at least one empty space in the column.
     */
    auto insertionRow = 0u;
    for (auto i = 0; i < ROWS; i++) {
        if ((board.at(i)).at(columnIndex) == EMPTY_SPACE) {
            insertionRow = i;
            (board.at(i)).at(columnIndex) = opponentMove ? OPPONENT_TOKEN : MY_TOKEN;
            break;
        }
    }

    if (checkWinOnVerticalLine(insertionRow, columnIndex, opponentMove)
        || checkWinOnHorizontalLine(insertionRow, columnIndex, opponentMove)
        || checkWinOnLeftDiagonalLine(insertionRow, columnIndex, opponentMove)
        || checkWinOnRightDiagonalLine(insertionRow, columnIndex, opponentMove)) {
        matchFinished = true;
        result = opponentMove ? Result::LOSS : Result::WIN;
        return true;
    }

    if (turn == ROWS * COLUMNS) {
        matchFinished = true;
        result = Result::DRAW;
    }

    return true;
}

bool FourInARow::checkWinOnVerticalLine(const uint8_t &rowIndex, const uint8_t &columnIndex, bool opponentMove) {
    if (rowIndex >= ROWS || columnIndex >= COLUMNS || rowIndex < 3) {
        return false;
    }

    for (int i = rowIndex; i >= rowIndex - 3; i--) {
        if ((!opponentMove && (board.at(i)).at(columnIndex) == OPPONENT_TOKEN)
            || (opponentMove && (board.at(i)).at(columnIndex) == MY_TOKEN)) {

            return false;
        }

        if ((board.at(i)).at(columnIndex) == EMPTY_SPACE) {
            
            cerr << "Implementation error: empty space under token (";
            cerr << unsigned(rowIndex) << ',' << unsigned(columnIndex) << ')' << endl;

            return false;
        }
    }

    return true;
}

bool FourInARow::checkWinOnHorizontalLine(const uint8_t &rowIndex, const uint8_t &columnIndex, bool opponentMove) {
    if (rowIndex >= ROWS || columnIndex >= COLUMNS) {
        return false;
    }

    /*
     * Examine all the possible horizontal lines of four discs including the given disc.
     * The approach is based on a horizontal sliding window of size N=4. At the beginning, the window
     * starts on position (rowIndex, columnIndex - 3) and ends on position (rowIndex, columnIndex);
     * then, the starting point gets its column index increased by one every time a non-winning combination
     * is found. The last sliding window starts at (rowIndex, columnIndex) and ends at (rowIndex, columnIndex + 3).
     */
    for (int i = columnIndex - 3; i <= columnIndex; i++) {
        if (i < 0) { // Invalid sliding window.
            continue;
        }

        if (i + 3 >= COLUMNS) { // From this point on, the sliding window cannot include four discs anymore.
            break;
        }

        auto valid = true;
        for (int j = i; j <= i + 3; j++) {
            if ((opponentMove && (board.at(rowIndex)).at(j) == OPPONENT_TOKEN)
                || (!opponentMove && (board.at(rowIndex)).at(j) == MY_TOKEN)) {
                continue;
            }
            valid = false;
            break;
        }

        if (valid) {
            return true;
        }
    }

    return false;
}

bool FourInARow::checkWinOnLeftDiagonalLine(const uint8_t &rowIndex, const uint8_t &columnIndex, bool opponentMove) {
    if (rowIndex >= ROWS || columnIndex >= COLUMNS) {
        return false;
    }

    /*
     * Examine all the possible left diagonal lines of four discs including the given disc.
     * The approach is based on a diagonal sliding window of size N=4. At the beginning, the window
     * starts on position (rowIndex + 3, columnIndex - 3) and ends on position (rowIndex, columnIndex);
     * then, the starting point gets its row index decreased by one and its column index increased by one
     * every time a non-winning combination is found. The last sliding window
     * starts at (rowIndex, columnIndex) and ends at (rowIndex - 3, columnIndex + 3).
     */
    for (int i = rowIndex + 3, j = columnIndex - 3; i >= rowIndex && j <= columnIndex; i--, j++) {
        if (i >= ROWS || j < 0) { // Invalid sliding window.
            continue;
        }

        if (i - 3 < 0 || j + 3 >= COLUMNS) { // From this point on, the sliding window cannot include four discs anymore.
            break;
        }

        auto valid = true;
        for (int h = i, k = j; h >= i - 3 && k <= j + 3; h--, k++) {
            if ((opponentMove && (board.at(h)).at(k) == OPPONENT_TOKEN) || 
                (!opponentMove && (board.at(h)).at(k) == MY_TOKEN)) {

                continue;
            }
            valid = false;
            break;
        }

        if (valid) {
            return true;
        }
    }

    return false;
}

bool FourInARow::checkWinOnRightDiagonalLine(const uint8_t &rowIndex, const uint8_t &columnIndex, bool opponentMove) {
    if (rowIndex >= ROWS || columnIndex >= COLUMNS) {
        return false;
    }

    /*
     * Examine all the possible right diagonal lines of four discs including the given disc.
     * The approach is based on a diagonal sliding window of size N=4. At the beginning, the window
     * starts on position (rowIndex + 3, columnIndex + 3) and ends on position (rowIndex, columnIndex);
     * then, the starting point gets both its row and column indexes decreased by one
     * every time a non-winning combination is found. The last sliding window
     * starts at (rowIndex, columnIndex) and ends at (rowIndex - 3, columnIndex - 3).
     */
    for (int i = rowIndex + 3, j = columnIndex + 3; i >= rowIndex && j >= columnIndex; i--, j--) {
        if (i >= ROWS || j >= COLUMNS) { // Invalid sliding window.
            continue;
        }

        if (i - 3 < 0 || j - 3 < 0) { // From this point on, the sliding window cannot include four discs anymore.
            break;
        }

        auto valid = true;
        for (int h = i, k = j; h >= i - 3 && k >= j - 3; h--, k--) {
            if ((opponentMove && (board.at(h)).at(k) == OPPONENT_TOKEN) || 
                    (!opponentMove && (board.at(h)).at(k) == MY_TOKEN)) {

                continue;

            }
            valid = false;
            break;
        }

        if (valid) {
            return true;
        }
    }

    return false;
}

bool FourInARow::isMatchFinished(){
    return matchFinished;
}

FourInARow::Result FourInARow::getResult(){
    return result;
}

uint8_t FourInARow::userTurn(){

    cout << "Insert a column number between 0 and " << to_string(COLUMNS - 1) << ": " << flush;

    uint16_t column = 0;

    cin >> column;

    while (column >= COLUMNS || !registerMove(column, false)) {
        
        cout << "Invalid input. Please enter a valid column index: " << flush;
        clearStdin();
        cin >> column;
    }

    clearStdin();

    return column;

}

bool FourInARow::opponentTurn(uint16_t column_index){

    if(!registerMove(column_index, true)){

        cout << getOpponent() << " is trying to cheat. Closing the communication...\n" << endl;
        return false;

    }

    return true;
}

string FourInARow::toString() const {
    string boardPrint;

    for (int i = ROWS - 1; i >= 0; i--) {

        for (auto &j : board.at(i)) {

            if (j == EMPTY_SPACE) {
                boardPrint += "|   ";
                continue;
            }
            if (j == MY_TOKEN) {
                boardPrint += "| O ";
                continue;
            }
            if (j == OPPONENT_TOKEN) {
                boardPrint += "| X ";
                continue;
            }

        }
        boardPrint += "|\n";
    }

    for (int i = 0; i < COLUMNS; i++) {

        if (i == (COLUMNS - 1)) {

            boardPrint += "-----\n";

        } else {

            boardPrint += "----";

        }
    }

    /*
     * Print the column index. This works only
     * if numberOfColumns <= 9, otherwise the
     * indexes come out not aligned.
     */
    for (auto i = 0; i < COLUMNS; i++) {
        boardPrint += ("  " + to_string(i) + " ");
    }

    boardPrint += ("\n\nYou: O   " + opponent + ": X   Turn: " + to_string(turn)) + "\n";
    return boardPrint;
}