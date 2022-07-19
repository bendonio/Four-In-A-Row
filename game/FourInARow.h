#ifndef FOUR_IN_A_ROW_H
#define FOUR_IN_A_ROW_H

#include <vector>

using namespace std;


class FourInARow {

    public:
        enum class Result { WIN, DRAW, LOSS };

    private:

        bool matchFinished;
        Result result;
        unsigned int turn;
        vector<vector<int>> board;
        string opponent;
        
    public:
        
        FourInARow(string opponent);

        bool isMatchFinished();

        uint8_t userTurn();

        bool opponentTurn(uint16_t column_index);

        bool registerMove(const uint8_t columnIndex, bool opponentMove);

        bool isValidMove(const uint8_t &columnIndex);

        bool checkWinOnVerticalLine(const uint8_t &rowIndex, const uint8_t &columnIndex, bool opponentMove);
        
        bool checkWinOnHorizontalLine(const uint8_t &rowIndex, const uint8_t &columnIndex, bool opponentMove);

        bool checkWinOnLeftDiagonalLine(const uint8_t &rowIndex, const uint8_t &columnIndex, bool opponentMove);
        
        bool checkWinOnRightDiagonalLine(const uint8_t &rowIndex, const uint8_t &columnIndex, bool opponentMove);

        FourInARow::Result getResult();

        const string& getOpponent(){ return opponent;}


        /**
         * Returns a string representing the board, the tokens and the players.
         */
        string toString() const;
 

};


#endif