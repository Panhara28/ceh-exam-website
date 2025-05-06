"use client";

import { useState } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

type LearningInterfaceProps = {
  learningData: any[];
};

export default function LearningInterface({
  learningData,
}: LearningInterfaceProps) {
  const [questionsPerPage, setQuestionsPerPage] = useState(10);
  const [currentPage, setCurrentPage] = useState(1);

  // Calculate pagination
  const totalQuestions = learningData.length;
  const totalPages = Math.ceil(totalQuestions / questionsPerPage);
  const startIndex = (currentPage - 1) * questionsPerPage;
  const endIndex = Math.min(startIndex + questionsPerPage, totalQuestions);
  const currentQuestions = learningData.slice(startIndex, endIndex);

  // Handle page change
  const handlePageChange = (page: number) => {
    setCurrentPage(page);
  };

  function generatePaginationButtons() {
    // For small number of pages, show all
    if (totalPages <= 7) {
      return Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
        <Button
          key={page}
          variant={currentPage === page ? "default" : "outline"}
          size="sm"
          onClick={() => handlePageChange(page)}
          className="w-8 h-8 p-0 mb-1"
        >
          {page}
        </Button>
      ));
    }

    // For larger number of pages, show first, last, and pages around current
    const items = [];

    // Always add first page
    items.push(
      <Button
        key={1}
        variant={currentPage === 1 ? "default" : "outline"}
        size="sm"
        onClick={() => handlePageChange(1)}
        className="w-8 h-8 p-0 mb-1"
      >
        1
      </Button>
    );

    // Add ellipsis if needed
    if (currentPage > 3) {
      items.push(
        <span key="start-ellipsis" className="px-2">
          ...
        </span>
      );
    }

    // Add pages around current page
    const startPage = Math.max(2, currentPage - 1);
    const endPage = Math.min(totalPages - 1, currentPage + 1);

    for (let i = startPage; i <= endPage; i++) {
      if (i <= totalPages - 1 && i >= 2) {
        items.push(
          <Button
            key={i}
            variant={currentPage === i ? "default" : "outline"}
            size="sm"
            onClick={() => handlePageChange(i)}
            className="w-8 h-8 p-0 mb-1"
          >
            {i}
          </Button>
        );
      }
    }

    // Add ellipsis if needed
    if (currentPage < totalPages - 2) {
      items.push(
        <span key="end-ellipsis" className="px-2">
          ...
        </span>
      );
    }

    // Always add last page
    if (totalPages > 1) {
      items.push(
        <Button
          key={totalPages}
          variant={currentPage === totalPages ? "default" : "outline"}
          size="sm"
          onClick={() => handlePageChange(totalPages)}
          className="w-8 h-8 p-0 mb-1"
        >
          {totalPages}
        </Button>
      );
    }

    return items;
  }

  return (
    <div className="container mx-auto py-8 px-4 max-w-4xl">
      <h1 className="text-2xl font-bold mb-6 text-center">
        Computer Hacking Forensic Investigator (CHFI) Exam Practice
      </h1>

      <div className="flex justify-between items-center mb-6">
        <div className="text-sm">
          Showing {startIndex + 1}-{endIndex} of {totalQuestions} questions
        </div>

        <div className="flex items-center gap-2">
          <span className="text-sm">Questions per page:</span>
          <Select
            value={questionsPerPage.toString()}
            onValueChange={(value) => {
              setQuestionsPerPage(Number(value));
              setCurrentPage(1);
            }}
          >
            <SelectTrigger className="w-20">
              <SelectValue placeholder="10" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="10">10</SelectItem>
              <SelectItem value="20">20</SelectItem>
              <SelectItem value="50">50</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="space-y-6">
        {currentQuestions.map((question) => (
          <Card key={question.id} className="shadow-sm">
            <CardContent className="pt-6">
              <div className="mb-4">
                <span className="font-semibold text-sm bg-gray-100 px-2 py-1 rounded-md mr-2">
                  Question {question.id}
                </span>
                <p className="mt-2">{question.question}</p>
              </div>

              <div className="space-y-2 mt-4">
                {question.options.map((option: any, index: number) => (
                  <div
                    key={index}
                    className={`p-3 rounded-md border ${
                      index === question.correctAnswer
                        ? "bg-green-50 border-green-200"
                        : "bg-white border-gray-200"
                    }`}
                  >
                    <div className="flex items-start">
                      <div className="mr-2 font-medium">
                        {String.fromCharCode(65 + index)}.
                      </div>
                      <div>{option}</div>
                      {index === question.correctAnswer && (
                        <div className="ml-auto text-green-600 text-sm font-medium">
                          Correct Answer
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex flex-col sm:flex-row justify-between items-center gap-4 mt-8">
        <Button
          variant="outline"
          onClick={() => handlePageChange(currentPage - 1)}
          disabled={currentPage === 1}
          className="flex items-center gap-1"
        >
          <ChevronLeft className="h-4 w-4" />
          Previous
        </Button>

        <div className="flex items-center gap-1 flex-wrap justify-center">
          {generatePaginationButtons()}
        </div>

        <Button
          variant="outline"
          onClick={() => handlePageChange(currentPage + 1)}
          disabled={currentPage === totalPages}
          className="flex items-center gap-1"
        >
          Next
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}
