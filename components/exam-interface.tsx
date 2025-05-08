"use client";

import { useState, useEffect, useMemo } from "react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import {
  Clock,
  ChevronLeft,
  ChevronRight,
  RotateCcw,
  CheckCircle,
  AlertCircle,
  ArrowLeft,
} from "lucide-react";

// Type for storing answers by question ID
type AnswerMap = {
  [questionId: number]: number | null;
};

type ExamInterfaceProps = {
  dataQuestions: any;
};

export default function ExamInterface({ dataQuestions }: ExamInterfaceProps) {
  const [questions, setQuestions]: any = useState([]);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<(number | null)[]>([]);
  const [timeRemaining, setTimeRemaining] = useState(60 * 60); // 60 minutes in seconds
  const [examSubmitted, setExamSubmitted] = useState(false);
  const [showResults, setShowResults] = useState(false);
  const [reviewMode, setReviewMode] = useState(false);
  const [examStarted, setExamStarted] = useState(false);

  // Function to shuffle the questions array
  const shuffleQuestions = () => {
    // Create a copy of the original questions
    const shuffled = [...dataQuestions];

    // Fisher-Yates shuffle algorithm
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }

    return shuffled;
  };

  // Convert array of answers to a map of question ID -> answer
  const answersToMap = (
    questions: any[],
    answers: (number | null)[]
  ): AnswerMap => {
    const answerMap: AnswerMap = {};
    questions.forEach((question, index) => {
      answerMap[question.id] = answers[index];
    });
    return answerMap;
  };

  // Convert map of question ID -> answer back to array based on current question order
  const mapToAnswers = (
    questions: any[],
    answerMap: AnswerMap
  ): (number | null)[] => {
    return questions.map((question) => answerMap[question.id] ?? null);
  };

  // Initialize the exam with randomized questions
  useEffect(() => {
    // Always shuffle questions on page load
    const randomizedQuestions: any = shuffleQuestions();

    // Check if there's saved state in localStorage
    const savedState = loadExamState();

    if (savedState) {
      // Convert saved answers to a map by question ID
      const answerMap = answersToMap(
        savedState.questions,
        savedState.selectedAnswers
      );

      // Map the answers to the new shuffled question order
      const remappedAnswers = mapToAnswers(randomizedQuestions, answerMap);

      // Restore saved state but with newly shuffled questions
      setQuestions(randomizedQuestions);
      setCurrentQuestionIndex(savedState.currentQuestionIndex);
      setSelectedAnswers(remappedAnswers);
      setTimeRemaining(savedState.timeRemaining);
      setExamSubmitted(savedState.examSubmitted);
      setShowResults(savedState.showResults);
      setReviewMode(savedState.reviewMode);
    } else {
      // Start fresh with randomized questions
      setQuestions(randomizedQuestions);
      setSelectedAnswers(Array(randomizedQuestions.length).fill(null));
    }

    setExamStarted(true);
  }, []);

  // Save state to localStorage whenever it changes
  useEffect(() => {
    if (examStarted) {
      saveExamState();
    }
  }, [
    questions,
    currentQuestionIndex,
    selectedAnswers,
    timeRemaining,
    examSubmitted,
    showResults,
    reviewMode,
    examStarted,
  ]);

  // Timer effect
  useEffect(() => {
    if (examStarted && !examSubmitted && !showResults) {
      const timer = setInterval(() => {
        setTimeRemaining((prev) => {
          if (prev <= 1) {
            clearInterval(timer);
            handleSubmitExam();
            return 0;
          }
          return prev - 1;
        });
      }, 1000);

      return () => clearInterval(timer);
    }
  }, [examStarted, examSubmitted, showResults]);

  // Save exam state to localStorage
  const saveExamState = () => {
    const state = {
      questions,
      currentQuestionIndex,
      selectedAnswers,
      timeRemaining,
      examSubmitted,
      showResults,
      reviewMode,
    };

    localStorage.setItem("examState", JSON.stringify(state));
  };

  // Load exam state from localStorage
  const loadExamState = () => {
    const savedState = localStorage.getItem("examState");
    return savedState ? JSON.parse(savedState) : null;
  };

  // Clear saved state
  const clearSavedState = () => {
    localStorage.removeItem("examState");
  };

  const handleAnswerSelect = (answerIndex: number) => {
    const newSelectedAnswers = [...selectedAnswers];
    newSelectedAnswers[currentQuestionIndex] = answerIndex;
    setSelectedAnswers(newSelectedAnswers);
  };

  const handleNextQuestion = () => {
    if (currentQuestionIndex < questions.length - 1) {
      setCurrentQuestionIndex(currentQuestionIndex + 1);
    }
  };

  const handlePreviousQuestion = () => {
    if (currentQuestionIndex > 0) {
      setCurrentQuestionIndex(currentQuestionIndex - 1);
    }
  };

  const handleReviewExam = () => {
    setReviewMode(true);
  };

  const handleBackToExam = () => {
    setReviewMode(false);
  };

  const handleSubmitExam = () => {
    setExamSubmitted(true);
    setShowResults(true);
    setReviewMode(false);
  };

  const handleRestartExam = () => {
    // Clear saved state
    clearSavedState();

    // Randomize questions again
    const randomizedQuestions: any = shuffleQuestions();
    console.log(
      "Questions re-randomized on restart:",
      randomizedQuestions.map((q: any) => q.id)
    );

    setQuestions(randomizedQuestions);
    setSelectedAnswers(Array(randomizedQuestions.length).fill(null));
    setCurrentQuestionIndex(0);
    setTimeRemaining(60 * 60);
    setExamSubmitted(false);
    setShowResults(false);
    setReviewMode(false);
  };

  const calculateScore = () => {
    let correctCount = 0;
    selectedAnswers.forEach((selected: any, index: any) => {
      if (selected === questions[index]?.correctAnswer) {
        correctCount++;
      }
    });
    return {
      score: correctCount,
      total: questions.length,
      percentage:
        questions.length > 0
          ? Math.round((correctCount / questions.length) * 100)
          : 0,
    };
  };

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, "0")}:${secs
      .toString()
      .padStart(2, "0")}`;
  };

  const getUnansweredCount = () => {
    return selectedAnswers.filter((answer) => answer === null).length;
  };

  // If questions haven't loaded yet, show a loading state
  if (!examStarted || questions.length === 0) {
    return (
      <Card>
        <CardContent className="flex justify-center items-center py-12">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
            <p>Loading exam questions...</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const currentQuestion: any = questions[currentQuestionIndex];
  const score = calculateScore();
  const unansweredCount = getUnansweredCount();

  if (reviewMode) {
    return (
      <div className="space-y-6">
        <div className="flex justify-between items-center mb-4">
          <Button
            variant="outline"
            onClick={handleBackToExam}
            className="flex items-center"
          >
            <ArrowLeft className="h-4 w-4 mr-2" /> Back to Exam
          </Button>
          <div className="flex items-center space-x-2 text-orange-600 dark:text-orange-400">
            <Clock className="h-5 w-5" />
            <span className="font-medium">{formatTime(timeRemaining)}</span>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="text-2xl text-center">
              Review Your Answers
            </CardTitle>
            {unansweredCount > 0 && (
              <div className="mt-2 p-2 bg-amber-50 border border-amber-200 rounded-md text-amber-700 text-center dark:bg-amber-900/20 dark:border-amber-800 dark:text-amber-400">
                <AlertCircle className="h-4 w-4 inline-block mr-2" />
                You have {unansweredCount} unanswered question
                {unansweredCount > 1 ? "s" : ""}
              </div>
            )}
          </CardHeader>
          <CardContent className="space-y-4">
            {questions.map((q: any, index: any) => (
              <div
                key={index}
                className="border rounded-md p-4 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
              >
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <h3 className="font-medium">
                      Question {index + 1}:{" "}
                      {q.question.length > 100
                        ? q.question.substring(0, 100) + "..."
                        : q.question}
                    </h3>
                    {selectedAnswers[index] !== null ? (
                      <p className="mt-2 text-gray-700 dark:text-gray-300">
                        Your answer:{" "}
                        {q.options[selectedAnswers[index] as number]}
                      </p>
                    ) : (
                      <p className="mt-2 text-red-500 dark:text-red-400">
                        Not answered
                      </p>
                    )}
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setCurrentQuestionIndex(index);
                      setReviewMode(false);
                    }}
                  >
                    Edit
                  </Button>
                </div>
              </div>
            ))}
          </CardContent>
          <CardFooter className="flex justify-between">
            <Button variant="outline" onClick={handleBackToExam}>
              Continue Editing
            </Button>
            <Button onClick={handleSubmitExam}>Submit Exam</Button>
          </CardFooter>
        </Card>
      </div>
    );
  }

  if (showResults) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-2xl text-center">Exam Results</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="text-center">
            <div className="text-5xl font-bold mb-2">{score.percentage}%</div>
            <p className="text-xl">
              You scored {score.score} out of {score.total}
            </p>

            {score.percentage >= 70 ? (
              <div className="mt-4 p-4 bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100 rounded-md">
                <CheckCircle className="h-5 w-5 inline-block mr-2" />
                Congratulations! You have passed the practice exam.
              </div>
            ) : (
              <div className="mt-4 p-4 bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100 rounded-md">
                <AlertCircle className="h-5 w-5 inline-block mr-2" />
                You did not pass this attempt. Review the questions and try
                again.
              </div>
            )}
          </div>

          <div className="space-y-4 mt-8">
            <h3 className="text-xl font-semibold">Question Review</h3>
            {questions.map((q: any, index: any) => (
              <div
                key={index}
                className={`p-4 rounded-md ${
                  selectedAnswers[index] === q.correctAnswer
                    ? "bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800"
                    : "bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800"
                }`}
              >
                <p className="font-medium">
                  {index + 1}. {q.question}
                </p>
                <div className="mt-2 ml-4">
                  {q.options.map((option: any, optIndex: any) => {
                    if (optIndex === q.correctAnswer) {
                      return (
                        <div
                          key={optIndex}
                          className={`py-1 ${
                            optIndex === q.correctAnswer
                              ? "text-green-700 dark:text-green-400 font-medium"
                              : optIndex === selectedAnswers[index]
                              ? "text-red-700 dark:text-red-400 font-medium"
                              : ""
                          }`}
                        >
                          <div
                            key={optIndex}
                            className={`py-1 ${
                              optIndex === q.correctAnswer
                                ? "text-green-700 dark:text-green-400 font-medium"
                                : optIndex === selectedAnswers[index]
                                ? "text-red-700 dark:text-red-400 font-medium"
                                : ""
                            }`}
                          >
                            {option} {optIndex === q.correctAnswer && "✓"}
                          </div>
                        </div>
                      );
                    }
                  })}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
        <CardFooter>
          <Button onClick={handleRestartExam} className="w-full">
            <RotateCcw className="mr-2 h-4 w-4" /> Restart Exam
          </Button>
        </CardFooter>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center mb-4">
        <div className="flex items-center space-x-2">
          <span className="font-medium">
            Question {currentQuestionIndex + 1} of {questions.length}
          </span>
          <Progress
            value={((currentQuestionIndex + 1) / questions.length) * 100}
            className="w-32"
          />
        </div>
        <div className="flex items-center space-x-2 text-orange-600 dark:text-orange-400">
          <Clock className="h-5 w-5" />
          <span className="font-medium">{formatTime(timeRemaining)}</span>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-xl">{currentQuestion.question}</CardTitle>
        </CardHeader>
        <CardContent>
          <RadioGroup
            value={selectedAnswers[currentQuestionIndex]?.toString() || ""}
            onValueChange={(value) =>
              handleAnswerSelect(Number.parseInt(value))
            }
          >
            <RenderOptions currentQuestion={currentQuestion} />
          </RadioGroup>
        </CardContent>
        <CardFooter className="flex justify-between">
          <Button
            variant="outline"
            onClick={handlePreviousQuestion}
            disabled={currentQuestionIndex === 0}
          >
            <ChevronLeft className="mr-2 h-4 w-4" /> Previous
          </Button>

          {currentQuestionIndex === questions.length - 1 ? (
            <Button onClick={handleReviewExam}>Review Answers</Button>
          ) : (
            <Button onClick={handleNextQuestion}>
              Next <ChevronRight className="ml-2 h-4 w-4" />
            </Button>
          )}
        </CardFooter>
      </Card>

      <div className="flex flex-wrap mt-6">
        {questions.map((_: any, index: any) => (
          <Button
            key={index}
            variant={
              index === currentQuestionIndex
                ? "default"
                : selectedAnswers[index] !== null
                ? "secondary"
                : "outline"
            }
            className="h-7 w-7 p-0 text-xs m-0.5 rounded-sm"
            onClick={() => setCurrentQuestionIndex(index)}
          >
            {index + 1}
          </Button>
        ))}
      </div>
    </div>
  );
}

const RenderOptions = ({ currentQuestion }: any) => {
  const shuffledOptions = useMemo(() => {
    const rendered = currentQuestion.options.map((option: any, index: any) => (
      <div key={index} className="flex items-center space-x-2 py-2">
        <RadioGroupItem value={index.toString()} id={`option-${index}`} />
        <Label htmlFor={`option-${index}`} className="cursor-pointer">
          {option}
        </Label>
      </div>
    ));

    // Shuffle once when currentQuestion changes
    for (let i = rendered.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [rendered[i], rendered[j]] = [rendered[j], rendered[i]];
    }

    return rendered;
  }, [currentQuestion]);

  return <div>{shuffledOptions}</div>;
};
